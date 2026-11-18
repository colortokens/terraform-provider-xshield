package keyservice

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// connectionFault makes the key service's connection fail instead of answering.
type connectionFault string

const (
	closedBeforeAnswering connectionFault = "dropped connection"
	resetBeforeAnswering  connectionFault = "reset connection"
	closedMidAnswer       connectionFault = "truncated response"
)

type scriptedResponse struct {
	status int
	header http.Header
	body   string
	fault  connectionFault
}

func (r scriptedResponse) String() string {
	if r.fault != "" {
		return string(r.fault)
	}
	return fmt.Sprintf("%d %s", r.status, r.body)
}

func (r scriptedResponse) withRetryAfter(value string) scriptedResponse {
	r.header = http.Header{"Retry-After": []string{value}}
	return r
}

func awsKMSFailure(status int, errorType, message string) scriptedResponse {
	return scriptedResponse{status: status, body: fmt.Sprintf(`{"__type":%q,"message":%q}`, errorType, message)}
}

func keyVaultFailure(status int, code, message string) scriptedResponse {
	return scriptedResponse{status: status, body: fmt.Sprintf(`{"error":{"code":%q,"message":%q}}`, code, message)}
}

func cloudKMSFailure(status int, code, message string) scriptedResponse {
	return scriptedResponse{status: status, body: fmt.Sprintf(`{"error":{"code":%d,"status":%q,"message":%q}}`, status, code, message)}
}

var (
	droppedConnection = scriptedResponse{fault: closedBeforeAnswering}
	resetConnection   = scriptedResponse{fault: resetBeforeAnswering}
	truncatedResponse = scriptedResponse{fault: closedMidAnswer}
)

// scriptedKeyService answers the first sign calls from a script and passes every other call to the fake key service.
type scriptedKeyService struct {
	next      http.RoundTripper
	isSign    func(*http.Request) bool
	script    []scriptedResponse
	signCalls atomic.Int32
	dropping  *httptest.Server
}

func (s *scriptedKeyService) RoundTrip(req *http.Request) (*http.Response, error) {
	if !s.isSign(req) {
		return s.next.RoundTrip(req)
	}
	call := int(s.signCalls.Add(1))
	if call > len(s.script) {
		return s.next.RoundTrip(req)
	}
	response := s.script[call-1]
	if response.fault != "" {
		dropped := req.Clone(req.Context())
		dropped.URL.Host = s.dropping.Listener.Addr().String()
		dropped.Host = ""
		dropped.Header.Set("X-Connection-Fault", string(response.fault))
		return s.dropping.Client().Transport.RoundTrip(dropped)
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	header := response.header
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: response.status, Status: fmt.Sprintf("%d %s", response.status, http.StatusText(response.status)),
		Header: header, Body: io.NopCloser(strings.NewReader(response.body)), Request: req}, nil
}

func (s *scriptedKeyService) around(client *http.Client) *http.Client {
	s.next = client.Transport
	return &http.Client{Transport: s}
}

type recordedWaits struct {
	mu     sync.Mutex
	delays []time.Duration
}

// policy records each wait instead of sleeping, and backs off by the whole jitter limit so the delays are exact.
func (r *recordedWaits) policy() retryPolicy {
	return retryPolicy{
		wait: func(_ context.Context, delay time.Duration) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.delays = append(r.delays, delay)
			return nil
		},
		jitter: func(limit time.Duration) time.Duration { return limit },
	}
}

func (r *recordedWaits) recorded() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.delays)
}

type keyServiceUnderTest struct {
	name      string
	keyName   string
	throttled scriptedResponse
	isSign    func(*http.Request) bool
	build     func(t *testing.T, client func(*http.Client) *http.Client, retry retryPolicy) remoteKeyClient
}

var keyServicesUnderTest = map[string]keyServiceUnderTest{
	"aws": {
		name: "AWS KMS", keyName: testKeyARN,
		throttled: awsKMSFailure(http.StatusBadRequest, "com.amazonaws.kms#ThrottlingException", "Rate exceeded"),
		isSign:    func(r *http.Request) bool { return r.Header.Get("X-Amz-Target") == "TrentService.Sign" },
		build: func(t *testing.T, client func(*http.Client) *http.Client, retry retryPolicy) remoteKeyClient {
			key := fakeAWSKMS(t, "SIGN_VERIFY")
			key.client, key.retry = client(key.client), retry
			return key
		},
	},
	"azure": {
		name: "Azure Key Vault", keyName: "/keys/api-key/v2",
		throttled: keyVaultFailure(http.StatusTooManyRequests, "Throttled", "Request was not processed because too many requests were received"),
		isSign: func(r *http.Request) bool {
			return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sign")
		},
		build: func(t *testing.T, client func(*http.Client) *http.Client, retry retryPolicy) remoteKeyClient {
			var signedAt atomic.Value
			key := fakeKeyVault(t, "RSA-HSM", &signedAt)
			key.client, key.retry = client(key.client), retry
			return key
		},
	},
	"gcp": {
		name: "Google Cloud KMS", keyName: testKeyVersionName,
		throttled: cloudKMSFailure(http.StatusTooManyRequests, "RESOURCE_EXHAUSTED", "Quota exceeded for quota metric 'Cryptographic requests'"),
		isSign:    func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, ":asymmetricSign") },
		build: func(t *testing.T, client func(*http.Client) *http.Client, retry retryPolicy) remoteKeyClient {
			key := fakeCloudKMS(t, "RSA_SIGN_PSS_2048_SHA256")
			key.client, key.retry = client(key.client), retry
			return key
		},
	},
}

func (k keyServiceUnderTest) open(t *testing.T, retry retryPolicy, script ...scriptedResponse) (*RemoteKey, *scriptedKeyService) {
	t.Helper()
	dropping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		switch connectionFault(r.Header.Get("X-Connection-Fault")) {
		case closedMidAnswer:
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{\"Signature\":\"AAAA"))
		case resetBeforeAnswering:
			_ = conn.(*net.TCPConn).SetLinger(0)
		}
		_ = conn.Close()
	}))
	t.Cleanup(dropping.Close)
	scripted := &scriptedKeyService{isSign: k.isSign, script: script, dropping: dropping}
	opened, err := openKey(context.Background(), k.build(t, scripted.around, retry))
	if err != nil {
		t.Fatal(err)
	}
	return opened, scripted
}

var testDigest = sha256.Sum256([]byte("(request-target): get /api/assets"))

func repeated(response scriptedResponse, times int) []scriptedResponse {
	script := make([]scriptedResponse, times)
	for i := range script {
		script[i] = response
	}
	return script
}

func TestAThrottledOrFailedSignIsRetriedUntilItSucceeds(t *testing.T) {
	cases := []struct {
		service string
		failure scriptedResponse
	}{
		{"aws", keyServicesUnderTest["aws"].throttled},
		{"aws", awsKMSFailure(http.StatusTooManyRequests, "TooManyRequestsException", "Rate exceeded")},
		{"aws", awsKMSFailure(http.StatusInternalServerError, "KMSInternalException", "internal error")},
		{"aws", awsKMSFailure(http.StatusServiceUnavailable, "DependencyTimeoutException", "timed out")},
		{"aws", droppedConnection},
		{"aws", resetConnection},
		{"aws", truncatedResponse},
		{"azure", keyServicesUnderTest["azure"].throttled},
		{"azure", keyVaultFailure(http.StatusServiceUnavailable, "ServiceUnavailable", "try again")},
		{"azure", droppedConnection},
		{"azure", resetConnection},
		{"azure", truncatedResponse},
		{"gcp", keyServicesUnderTest["gcp"].throttled},
		{"gcp", cloudKMSFailure(http.StatusServiceUnavailable, "UNAVAILABLE", "try again")},
		{"gcp", cloudKMSFailure(http.StatusGatewayTimeout, "DEADLINE_EXCEEDED", "try again")},
		{"gcp", droppedConnection},
		{"gcp", resetConnection},
		{"gcp", truncatedResponse},
	}
	for _, c := range cases {
		service := keyServicesUnderTest[c.service]
		t.Run(service.name+" "+c.failure.String(), func(t *testing.T) {
			var waits recordedWaits
			key, scripted := service.open(t, waits.policy(), c.failure, c.failure)
			signature, err := key.SignSHA256Digest(context.Background(), testDigest[:])
			if err != nil {
				t.Fatalf("the third attempt should have signed: %v", err)
			}
			if err = rsa.VerifyPSS(key.PublicKey, crypto.SHA256, testDigest[:], signature, nil); err != nil {
				t.Errorf("the signature from the retry does not verify: %v", err)
			}
			if got := scripted.signCalls.Load(); got != 3 {
				t.Errorf("%d sign calls, want 3", got)
			}
			if got := waits.recorded(); len(got) != 2 {
				t.Errorf("waited %v, want once before each retry", got)
			}
		})
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	for _, service := range keyServicesUnderTest {
		t.Run(service.name, func(t *testing.T) {
			var waits recordedWaits
			key, _ := service.open(t, waits.policy(), service.throttled.withRetryAfter("7"))
			if _, err := key.SignSHA256Digest(context.Background(), testDigest[:]); err != nil {
				t.Fatal(err)
			}
			if got := waits.recorded(); !slices.Equal(got, []time.Duration{7 * time.Second}) {
				t.Errorf("waited %v, want the 7s Retry-After asked for", got)
			}
		})
	}
}

func TestRetryAfterIsReadAsSecondsOrAnHTTPDate(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"7":                             7 * time.Second,
		"0":                             0,
		"Fri, 02 Jan 2026 03:04:14 GMT": 9 * time.Second,
		"Fri, 02 Jan 2026 03:04:00 GMT": 0,
		"soon":                          0,
		"-3":                            0,
		"":                              0,
	} {
		if got := retryAfter(http.Header{"Retry-After": []string{value}}, now); got != want {
			t.Errorf("Retry-After %q = %s, want %s", value, got, want)
		}
	}
}

func TestWithoutRetryAfterTheWaitDoublesFromHalfASecond(t *testing.T) {
	var waits recordedWaits
	service := keyServicesUnderTest["aws"]
	key, scripted := service.open(t, waits.policy(), repeated(service.throttled, 4)...)
	if _, err := key.SignSHA256Digest(context.Background(), testDigest[:]); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}
	if got := waits.recorded(); !slices.Equal(got, want) {
		t.Errorf("jitter limits %v, want %v", got, want)
	}
	if got := scripted.signCalls.Load(); got != 5 {
		t.Errorf("%d sign calls, want 5", got)
	}
}

func TestFullJitterIsAnyWaitBelowItsLimit(t *testing.T) {
	const limit = 4 * time.Second
	distinct := map[time.Duration]bool{}
	for range 200 {
		delay := fullJitter(limit)
		if delay < 0 || delay >= limit {
			t.Fatalf("jitter %s is outside [0, %s)", delay, limit)
		}
		distinct[delay] = true
	}
	if len(distinct) < 100 {
		t.Errorf("%d distinct waits in 200, want them spread across the limit", len(distinct))
	}
}

func TestARefusalIsNotRetried(t *testing.T) {
	cases := []struct {
		service string
		refusal scriptedResponse
		cause   string
	}{
		{"aws", awsKMSFailure(http.StatusBadRequest, "AccessDeniedException", "not authorized to perform kms:Sign"), "AccessDeniedException"},
		{"aws", awsKMSFailure(http.StatusBadRequest, "com.amazonaws.kms#KMSInvalidStateException", "pending deletion"), "KMSInvalidStateException"},
		{"aws", awsKMSFailure(http.StatusBadRequest, "DisabledException", "key is disabled"), "DisabledException"},
		{"aws", awsKMSFailure(http.StatusBadRequest, "InvalidKeyUsageException", "wrong key usage"), "InvalidKeyUsageException"},
		{"aws", awsKMSFailure(http.StatusBadRequest, "ValidationException", "bad request"), "ValidationException"},
		{"azure", keyVaultFailure(http.StatusUnauthorized, "Unauthorized", "no token"), "Unauthorized"},
		{"azure", keyVaultFailure(http.StatusForbidden, "Forbidden", "the caller lacks keys/sign"), "Forbidden"},
		{"azure", keyVaultFailure(http.StatusBadRequest, "BadParameter", "bad algorithm"), "BadParameter"},
		{"azure", keyVaultFailure(http.StatusNotFound, "KeyNotFound", "no such key"), "KeyNotFound"},
		{"gcp", cloudKMSFailure(http.StatusForbidden, "PERMISSION_DENIED", "cloudkms.cryptoKeyVersions.useToSign denied"), "PERMISSION_DENIED"},
		{"gcp", cloudKMSFailure(http.StatusBadRequest, "FAILED_PRECONDITION", "the key version is disabled"), "FAILED_PRECONDITION"},
		{"gcp", cloudKMSFailure(http.StatusBadRequest, "INVALID_ARGUMENT", "bad digest"), "INVALID_ARGUMENT"},
		{"gcp", cloudKMSFailure(http.StatusUnauthorized, "UNAUTHENTICATED", "no token"), "UNAUTHENTICATED"},
		{"gcp", cloudKMSFailure(http.StatusNotImplemented, "UNIMPLEMENTED", "not supported"), "UNIMPLEMENTED"},
	}
	for _, c := range cases {
		service := keyServicesUnderTest[c.service]
		t.Run(service.name+" "+c.cause, func(t *testing.T) {
			var waits recordedWaits
			key, scripted := service.open(t, waits.policy(), c.refusal, c.refusal)
			_, err := key.SignSHA256Digest(context.Background(), testDigest[:])
			if err == nil || !strings.Contains(err.Error(), service.keyName) || !strings.Contains(err.Error(), c.cause) {
				t.Errorf("error = %v, want one naming %s and %s", err, service.keyName, c.cause)
			}
			if got := scripted.signCalls.Load(); got != 1 || len(waits.recorded()) != 0 {
				t.Errorf("%d sign calls after waiting %v, want exactly one call", got, waits.recorded())
			}
		})
	}
}

func TestGivingUpNamesTheKeyAndTheLastCause(t *testing.T) {
	for _, service := range keyServicesUnderTest {
		t.Run(service.name, func(t *testing.T) {
			script := make([]scriptedResponse, 0, maxKeyServiceAttempts+1)
			for attempt := 1; attempt <= maxKeyServiceAttempts+1; attempt++ {
				failure := service.throttled
				failure.body = strings.Replace(failure.body, `","message":"`, fmt.Sprintf(`","message":"attempt %d: `, attempt), 1)
				script = append(script, failure)
			}
			var waits recordedWaits
			key, scripted := service.open(t, waits.policy(), script...)
			_, err := key.SignSHA256Digest(context.Background(), testDigest[:])
			if err == nil {
				t.Fatal("signed while the key service throttled every call")
			}
			for _, phrase := range []string{service.keyName, "attempt 5:", "gave up after 5 attempts"} {
				if !strings.Contains(err.Error(), phrase) {
					t.Errorf("the error does not mention %q: %v", phrase, err)
				}
			}
			if got := scripted.signCalls.Load(); got != maxKeyServiceAttempts {
				t.Errorf("%d sign calls, want %d", got, maxKeyServiceAttempts)
			}
		})
	}
}

func TestCancellingTheRequestStopsTheRetries(t *testing.T) {
	service := keyServicesUnderTest["aws"]
	key, scripted := service.open(t, retryPolicy{}, repeated(service.throttled.withRetryAfter("20"), 10)...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(100*time.Millisecond, cancel)

	done := make(chan error, 1)
	go func() {
		_, err := key.SignSHA256Digest(ctx, testDigest[:])
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "ThrottlingException") {
			t.Errorf("error = %v, want the cancellation and the throttling that preceded it", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting to retry after the request was cancelled")
	}
	if got := scripted.signCalls.Load(); got != 1 {
		t.Errorf("%d sign calls, want 1", got)
	}
}

func TestNoRetryIsStartedThatTheDeadlineCannotWaitFor(t *testing.T) {
	service := keyServicesUnderTest["gcp"]
	var waits recordedWaits
	key, scripted := service.open(t, waits.policy(), repeated(service.throttled.withRetryAfter("20"), 10)...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := key.SignSHA256Digest(ctx, testDigest[:])
	if err == nil || !strings.Contains(err.Error(), "deadline") || !strings.Contains(err.Error(), "RESOURCE_EXHAUSTED") {
		t.Errorf("error = %v, want the throttling and the deadline", err)
	}
	if got := scripted.signCalls.Load(); got != 1 || len(waits.recorded()) != 0 {
		t.Errorf("%d sign calls after waiting %v, want one call and no wait", got, waits.recorded())
	}
}

func TestARetryAfterBeyondTheLongestWaitIsNotWaitedFor(t *testing.T) {
	service := keyServicesUnderTest["azure"]
	var waits recordedWaits
	key, scripted := service.open(t, waits.policy(), repeated(service.throttled.withRetryAfter("3600"), 10)...)
	_, err := key.SignSHA256Digest(context.Background(), testDigest[:])
	if err == nil || !strings.Contains(err.Error(), "asked to wait 1h0m0s") || !strings.Contains(err.Error(), "Throttled") {
		t.Errorf("error = %v, want the throttling and the wait asked for", err)
	}
	if got := scripted.signCalls.Load(); got != 1 || len(waits.recorded()) != 0 {
		t.Errorf("%d sign calls after waiting %v, want one call and no wait", got, waits.recorded())
	}
}

package federation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeXshield stands in for the token endpoint and for one API route that accepts only the latest access token.
type fakeXshield struct {
	server    *httptest.Server
	exchanges atomic.Int32
	expiresIn int64
	refuse    string
	accepted  atomic.Value
	apiBodies []string
	mu        sync.Mutex
}

func newFakeXshield(t *testing.T) *fakeXshield {
	t.Helper()
	x := &fakeXshield{expiresIn: 900}
	x.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/oauth/token":
			x.serveToken(t, w, r)
		case "/api/assets":
			body, _ := io.ReadAll(r.Body)
			x.mu.Lock()
			x.apiBodies = append(x.apiBodies, string(body))
			x.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+x.accepted.Load().(string) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	x.accepted.Store("")
	t.Cleanup(x.server.Close)
	return x
}

func (x *fakeXshield) serveToken(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("token request %s with content type %q, want a form POST", r.Method, r.Header.Get("Content-Type"))
	}
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      "workload-oidc-token",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"tenant_id":          "tenant-1",
		"service_account_id": "111111111111",
	}
	for field, value := range want {
		if got := r.PostForm.Get(field); got != value {
			t.Errorf("token request %s = %q, want %q", field, got, value)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if x.refuse != "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": x.refuse, "error_description": "the token was not accepted for this service account"})
		return
	}
	token := "access-" + string(rune('0'+x.exchanges.Add(1)))
	x.accepted.Store(token)
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type": "Bearer", "expires_in": x.expiresIn})
}

func (x *fakeXshield) exchanger() *Exchanger {
	return NewExchanger(x.server.URL+"/", "tenant-1", "111111111111", staticToken("workload-oidc-token"), x.server.Client())
}

func TestTheExchangeSendsTheTokenExchangeGrantAndCachesTheAccessToken(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := x.exchanger()
	for range 3 {
		token, err := exchanger.AccessToken(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if token != "access-1" {
			t.Errorf("access token = %q, want access-1", token)
		}
	}
	if got := x.exchanges.Load(); got != 1 {
		t.Errorf("%d exchanges, want 1 while the access token is valid", got)
	}
}

func TestTheAccessTokenIsExchangedAgainInItsLastMinute(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := x.exchanger()
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	exchanger.now = func() time.Time { return clock }
	if _, err := exchanger.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(900*time.Second - 61*time.Second)
	if token, _ := exchanger.AccessToken(context.Background()); token != "access-1" {
		t.Errorf("with 61 s left the access token is %q, want the cached access-1", token)
	}
	clock = clock.Add(2 * time.Second)
	if token, _ := exchanger.AccessToken(context.Background()); token != "access-2" {
		t.Errorf("with 59 s left the access token is %q, want a new one", token)
	}
}

func TestARefusedExchangeSaysWhatToCheckWithoutTheToken(t *testing.T) {
	x := newFakeXshield(t)
	x.refuse = "invalid_grant"
	_, err := x.exchanger().AccessToken(context.Background())
	if err == nil {
		t.Fatal("a refused exchange returned an access token")
	}
	for _, phrase := range []string{"invalid_grant", "111111111111", "federation trusts", "issuer and audience"} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("the error does not mention %q: %v", phrase, err)
		}
	}
	if strings.Contains(err.Error(), "workload-oidc-token") {
		t.Errorf("the error prints the OIDC token: %v", err)
	}
}

func TestConcurrentRequestsShareOneExchange(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := x.exchanger()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := exchanger.AccessToken(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := x.exchanges.Load(); got != 1 {
		t.Errorf("%d exchanges for 20 concurrent requests, want 1", got)
	}
}

func bearerRequest(t *testing.T, exchanger *Exchanger, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	token, err := exchanger.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestA401IsRetriedOnceWithANewAccessToken(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := x.exchanger()
	client := NewReauthenticatingClient(x.server.Client(), exchanger)
	req := bearerRequest(t, exchanger, x.server.URL+"/api/assets", `{"name":"web-1"}`)
	x.accepted.Store("revoked-before-expiry")

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want the retry's 200", res.StatusCode)
	}
	if got := x.exchanges.Load(); got != 2 {
		t.Errorf("%d exchanges, want a second one after the 401", got)
	}
	if len(x.apiBodies) != 2 || x.apiBodies[1] != `{"name":"web-1"}` {
		t.Errorf("request bodies = %q, want the body sent again", x.apiBodies)
	}
}

func TestA401AfterTheRetryIsReturnedWithoutAnotherExchange(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := x.exchanger()
	client := NewReauthenticatingClient(refusingEveryRequest{x.server.Client()}, exchanger)
	res, err := client.Do(bearerRequest(t, exchanger, x.server.URL+"/api/assets", "{}"))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want the second 401", res.StatusCode)
	}
	if got := x.exchanges.Load(); got != 2 {
		t.Errorf("%d exchanges, want exactly one retry", got)
	}
}

type refusingEveryRequest struct{ next HTTPClient }

func (r refusingEveryRequest) Do(req *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(req.URL.Path, "/api/assets") {
		return r.next.Do(req)
	}
	return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func TestA401ToASignedRequestIsNotRetried(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := x.exchanger()
	client := NewReauthenticatingClient(x.server.Client(), exchanger)
	req, _ := http.NewRequest(http.MethodGet, x.server.URL+"/api/assets", nil)
	req.Header.Set("Authorization", `Signature version="1",keyId="tenant-1::111111111111::aa"`)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized || x.exchanges.Load() != 0 {
		t.Errorf("status %d after %d exchanges, want the 401 passed through untouched", res.StatusCode, x.exchanges.Load())
	}
}

func TestAFailedSubjectTokenStopsTheExchange(t *testing.T) {
	x := newFakeXshield(t)
	exchanger := NewExchanger(x.server.URL, "tenant-1", "111111111111", failingSource{}, x.server.Client())
	if _, err := exchanger.AccessToken(context.Background()); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("error = %v, want the token source's", err)
	}
	if x.exchanges.Load() != 0 {
		t.Error("exchanged without a subject token")
	}
}

type failingSource struct{}

func (failingSource) SubjectToken(context.Context) (string, error) {
	return "", errors.New("add permissions: id-token: write")
}

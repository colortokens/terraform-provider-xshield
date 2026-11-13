package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type recordedRequest struct {
	method, path, host string
	header             http.Header
	body               []byte
}

type recordingTransport struct {
	mu       sync.Mutex
	requests []recordedRequest
	next     http.RoundTripper
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	rt.mu.Lock()
	rt.requests = append(rt.requests, recordedRequest{method: req.Method, path: req.URL.RequestURI(), host: req.Host, header: req.Header.Clone(), body: body})
	rt.mu.Unlock()
	return rt.next.RoundTrip(req)
}

func newSnapshotTestAPI(t *testing.T, status int, response string) (cloudSnapshotAPI, *recordingTransport, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)

	recorder := &recordingTransport{next: srv.Client().Transport}
	client := sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", keyPEM)),
		sdk.WithClient(&http.Client{Transport: recorder}),
	)
	return cloudSnapshotAPI{client: client}, recorder, &key.PublicKey
}

// testVersion stands for a snapshot version, which Xshield names by its content hash.
var testVersion = strings.Repeat("ab", 64)

func TestSnapshotCallsUseTheProviderConfiguredClient(t *testing.T) {
	t.Parallel()
	// The provider block's proxy and timeout live on this client; a private
	// client would silently bypass a proxy the customer configured.
	api, recorder, _ := newSnapshotTestAPI(t, http.StatusOK, `{"version":"`+testVersion+`"}`)

	var exp wireExpected
	if err := api.get(context.Background(), api.endpoint(cloudAWS, "123456789012", "us-east-1", "expected"), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Version != testVersion || len(recorder.requests) != 1 {
		t.Fatalf("got version %s over %d requests through the configured client, want %s over 1", exp.Version, len(recorder.requests), testVersion)
	}
	if got := recorder.requests[0].path; got != "/api/policies/cloudsnapshots/aws/123456789012/us-east-1/expected" {
		t.Errorf("requested %s", got)
	}
}

func TestReceiptPostSignatureVerifiesOverTheBodySent(t *testing.T) {
	t.Parallel()
	api, recorder, pub := newSnapshotTestAPI(t, http.StatusCreated, `{"receiptId":"rcpt-1","appliedAt":"2026-01-02T03:04:05Z"}`)

	receipt := wireReceipt{Version: testVersion, Workspace: "ws", Resources: wireRenderedResources{
		SecurityGroups: map[string]string{"i-db-1": "sg-1"}, Rules: map[string]string{"k": "sgr-1"},
	}}
	if err := api.post(context.Background(), api.endpoint(cloudAWS, "123456789012", "us-east-1", "receipts"), receipt, http.StatusCreated, nil); err != nil {
		t.Fatal(err)
	}
	if len(recorder.requests) != 1 {
		t.Fatalf("%d requests went through the configured client, want 1", len(recorder.requests))
	}
	sent := recorder.requests[0]

	bodyDigest := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(sent.body)))
	if got, want := sent.header.Get("x-content-sha256"), base64.StdEncoding.EncodeToString(bodyDigest[:]); got != want {
		t.Fatalf("x-content-sha256 %q does not cover the body that was sent (want %q)", got, want)
	}

	auth := sent.header.Get("Authorization")
	match := regexp.MustCompile(`keyId="tenancy::user::fp".*headers="\(request-target\) date host x-content-sha256",signature="([^"]+)"`).FindStringSubmatch(auth)
	if match == nil {
		t.Fatalf("unexpected Authorization header: %s", auth)
	}
	signature, err := base64.RawStdEncoding.DecodeString(match[1])
	if err != nil {
		t.Fatal(err)
	}
	material := strings.Join([]string{
		"(request-target): post " + sent.path,
		"date: " + sent.header.Get("date"),
		"host: " + strings.Split(sent.host, ":")[0], // as the gateway reads it: without a port
		"x-content-sha256: " + sent.header.Get("x-content-sha256"),
	}, "\n")
	digest := sha256.Sum256([]byte(material))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, nil); err != nil {
		t.Errorf("signature does not verify over the request as sent: %v", err)
	}
}

func TestReceiptRejectionSurfacesWhatWasWrong(t *testing.T) {
	t.Parallel()
	api, _, _ := newSnapshotTestAPI(t, http.StatusUnprocessableEntity,
		`{"status":422,"message":"receipt does not account for exactly the snapshot's resources","details":{"rulesMissing":["i-db-1/in/tcp/5432/10.20.1.11/32"]}}`)

	err := api.post(context.Background(), api.endpoint(cloudAWS, "123456789012", "us-east-1", "receipts"), wireReceipt{}, http.StatusCreated, nil)
	if err == nil || !strings.Contains(err.Error(), "rulesMissing") || !strings.Contains(err.Error(), "5432") {
		t.Fatalf("error should name the missing rule, got %v", err)
	}
}

func TestReceiptRequestCarriesEveryRenderedID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mapOf := func(m map[string]string) types.Map {
		v, _ := types.MapValueFrom(ctx, types.StringType, m)
		return v
	}
	data := enforcementReceiptResourceModel{
		CloudAccountID:  types.StringValue("123456789012"),
		Region:          types.StringValue("us-east-1"),
		Workspace:       types.StringValue("ws"),
		SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups:  mapOf(map[string]string{"i-db-1": "sg-1"}),
		Rules:           mapOf(map[string]string{"i-db-1/in/tcp/5432/10.20.1.11/32": "sgr-1"}),
		Attachments:     types.MapNull(types.StringType),
	}
	req, diags := receiptRequest(ctx, &data, "run-123")
	if diags.HasError() {
		t.Fatal(diags)
	}
	if req.Version != testVersion || req.RunID != "run-123" ||
		req.Resources.SecurityGroups["i-db-1"] != "sg-1" || req.Resources.Rules["i-db-1/in/tcp/5432/10.20.1.11/32"] != "sgr-1" {
		t.Errorf("receipt request lost a value: %+v", req)
	}
	// An unset optional map must be sent as empty, not null, so Xshield compares
	// it against the snapshot's attachments rather than rejecting the receipt shape.
	if req.Resources.Attachments == nil || len(req.Resources.Attachments) != 0 {
		t.Errorf("unset attachments sent as %v, want an empty map", req.Resources.Attachments)
	}
}

func TestReceiptIsCurrentOnlyWhenXshieldHoldsThisReceipt(t *testing.T) {
	t.Parallel()
	if receiptIsCurrent(wireConvergence{}, "rcpt-1") {
		t.Error("no applied receipt in Xshield must not count as current")
	}
	if receiptIsCurrent(wireConvergence{Applied: &wireReceipt{ReceiptID: "rcpt-2"}}, "rcpt-1") {
		t.Error("a newer receipt from elsewhere must not count as current")
	}
	if !receiptIsCurrent(wireConvergence{Applied: &wireReceipt{ReceiptID: "rcpt-1"}}, "rcpt-1") {
		t.Error("the receipt Xshield holds must count as current")
	}
}

func TestReceiptTimeReadsTheSameWhenCreatedAndWhenImported(t *testing.T) {
	t.Parallel()
	const served = "2026-10-29T16:59:08.123456Z"
	api, _, _ := newSnapshotTestAPI(t, http.StatusCreated, `{"receiptId":"rcpt-1","appliedAt":"`+served+`"}`)
	r := &enforcementReceiptResource{api: api}
	created := enforcementReceiptResourceModel{CloudAccountID: types.StringValue("123456789012"), Region: types.StringValue("us-east-1"),
		Workspace: types.StringValue("ws"), SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups: types.MapNull(types.StringType), Rules: types.MapNull(types.StringType), Attachments: types.MapNull(types.StringType)}
	var diags diag.Diagnostics
	r.send(context.Background(), &created, &diags)
	var status wireConvergence
	if err := json.Unmarshal([]byte(`{"applied":{"receiptId":"rcpt-1","appliedAt":"`+served+`"}}`), &status); err != nil {
		t.Fatal(err)
	}
	var imported enforcementReceiptResourceModel
	r.adopt(context.Background(), &imported, status, &diags)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if !created.AppliedAt.Equal(imported.AppliedAt) || created.AppliedAt.ValueString() != served {
		t.Errorf("created %s, imported %s; want both %s", created.AppliedAt, imported.AppliedAt, served)
	}
}

// A snapshot over the provider's limit fails saying so, not as JSON cut off at the limit.
func TestASnapshotOverTheLimitFailsSayingSo(t *testing.T) {
	t.Parallel()
	api, _, _ := newSnapshotTestAPI(t, http.StatusOK, `{"rules":"`+strings.Repeat("x", maxSnapshotResponseBytes)+`"}`)

	var snapshot map[string]any
	err := api.get(context.Background(), api.endpoint(cloudAWS, "123456789012", "us-east-1", "snapshot"), &snapshot)

	if err == nil {
		t.Fatal("read a snapshot over the limit")
	}
	for _, want := range []string{"/123456789012/us-east-1/snapshot", "over the 32 MiB this provider reads", "Nothing was read or changed"} {
		if !strings.Contains(err.Error(), want) && !strings.Contains(err.Error(), strings.Replace(want, "over the", "larger than the", 1)) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "JSON") {
		t.Errorf("error %q reads as malformed JSON", err)
	}
}

func TestCustomerGroupChangesAreReadOncePerAccountAndRegion(t *testing.T) {
	t.Parallel()
	api, recorder, _ := newSnapshotTestAPI(t, http.StatusOK, `{"version":"v1","customerGroupChanges":{"vpc-1/web":{}}}`)

	var readers sync.WaitGroup
	for range 20 {
		readers.Go(func() {
			if changes, err := api.customerGroupChanges(context.Background(), "123456789012", "us-east-1"); err != nil || changes.Version != "v1" {
				t.Errorf("got version %q and error %v, want v1", changes.Version, err)
			}
		})
	}
	readers.Wait()
	if _, err := api.customerGroupChanges(context.Background(), "123456789012", "us-west-2"); err != nil {
		t.Fatal(err)
	}

	var paths []string
	for _, r := range recorder.requests {
		paths = append(paths, r.path)
	}
	want := []string{"/api/policies/cloudsnapshots/aws/123456789012/us-east-1/customergroupchanges",
		"/api/policies/cloudsnapshots/aws/123456789012/us-west-2/customergroupchanges"}
	if !slices.Equal(paths, want) {
		t.Errorf("requested %v, want each account and region once: %v", paths, want)
	}
}

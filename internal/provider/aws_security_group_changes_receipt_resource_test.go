package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/retry"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	changesReceiptAddress = "xshield_aws_security_group_changes_receipt.web"
	receiptsPath          = "/api/policies/cloudsnapshots/aws/123456789012/us-east-1/customergroupchanges/receipts"
	receiptUUID           = `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`
)

type signedRequest struct {
	method, requestURI string
	body               []byte
}

// gatewayServer serves the changes Xshield publishes for one account and region and takes receipts, after refusing,
// with 401 as the gateway does, any request whose signature the gateway would refuse.
type gatewayServer struct {
	t       *testing.T
	pub     *rsa.PublicKey
	keyPEM  string
	url     string
	mu      sync.Mutex
	changes string
	seen    []signedRequest
}

func newGatewayServer(t *testing.T) *gatewayServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &gatewayServer{t: t, pub: &key.PublicKey,
		keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	g.url = srv.URL
	return g
}

func (g *gatewayServer) providerBlock() string {
	return fmt.Sprintf(`
provider "xshield" {
  server_url  = %q
  tenancy_id  = "tenancy"
  user_id     = "user"
  fingerprint = "fp"
  private_key = <<EOT
%sEOT
}
`, g.url, g.keyPEM)
}

func (g *gatewayServer) api() cloudSnapshotAPI {
	return cloudSnapshotAPI{client: sdk.New(sdk.WithServerURL(g.url), sdk.WithClient(&http.Client{}),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", g.keyPEM)),
		sdk.WithRetryConfig(retry.Config{Strategy: "none"}))}
}

func (g *gatewayServer) serve(changes string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.changes = changes
}

func (g *gatewayServer) requests() []signedRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]signedRequest(nil), g.seen...)
}

func (g *gatewayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if err := gatewayVerifies(r, body, g.pub); err != nil {
		g.t.Errorf("the gateway would refuse %s %s: %v", r.Method, r.RequestURI, err)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, gatewayRefusal)
		return
	}
	g.mu.Lock()
	g.seen = append(g.seen, signedRequest{method: r.Method, requestURI: r.RequestURI, body: body})
	changes := g.changes
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customergroupchanges"):
		_, _ = io.WriteString(w, changes)
	case r.Method == http.MethodPost && r.URL.Path == receiptsPath:
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, receiptsPath+"/"):
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "404 page not found")
	}
}

// gatewayVerifies checks what the gateway checks: the digest of the body as sent, or of "nil" when there is none, and
// the signature over the method, the target with any query, the date, the host without its port and that digest.
func gatewayVerifies(r *http.Request, body []byte, pub *rsa.PublicKey) error {
	content := base64.StdEncoding.EncodeToString(body)
	if len(body) == 0 {
		content = base64.StdEncoding.EncodeToString([]byte("nil"))
	}
	digest := sha256.Sum256([]byte(content))
	if got, want := r.Header.Get("x-content-sha256"), base64.StdEncoding.EncodeToString(digest[:]); got != want {
		return fmt.Errorf("x-content-sha256 %q does not cover the body sent (%q)", got, want)
	}
	match := regexp.MustCompile(`headers="\(request-target\) date host x-content-sha256",signature="([^"]+)"`).
		FindStringSubmatch(r.Header.Get("Authorization"))
	if match == nil {
		return fmt.Errorf("not signed over the target, date, host and digest: %q", r.Header.Get("Authorization"))
	}
	signature, err := base64.RawStdEncoding.DecodeString(match[1])
	if err != nil {
		return err
	}
	material := sha256.Sum256([]byte(strings.Join([]string{
		"(request-target): " + strings.ToLower(r.Method) + " " + r.RequestURI,
		"date: " + r.Header.Get("date"),
		"host: " + strings.Split(r.Host, ":")[0],
		"x-content-sha256: " + r.Header.Get("x-content-sha256"),
	}, "\n")))
	return rsa.VerifyPSS(pub, crypto.SHA256, material[:], signature, nil)
}

func versionOf(n int) string { return strings.Repeat(fmt.Sprintf("%02x", n), 64) }

func servedChanges(version int, changeSets string) string {
	return fmt.Sprintf(`{"cloudAccountId":"123456789012","region":"us-east-1","version":%q,"customerGroupChanges":{`+
		`"vpc-0web/web":{"groupId":"sg-0web","revoke":[],"changeSets":[%s]}}}`, versionOf(version), changeSets)
}

func contractBody(id, label string, version int, changeSets string) string {
	labelField := ""
	if label != "" {
		labelField = fmt.Sprintf(`"label":%q,`, label)
	}
	return fmt.Sprintf(`{"id":%q,%s"version":%q,"groups":[{"groupId":"sg-0web","changeSets":[%s]}]}`, id, labelField, versionOf(version), changeSets)
}

func expectNoWorkspaceOrQuery(seen []signedRequest) error {
	for _, r := range seen {
		if strings.Contains(r.requestURI, "workspace") || strings.Contains(r.requestURI, "?") {
			return fmt.Errorf("%s %s names a workspace or carries a query", r.method, r.requestURI)
		}
	}
	return nil
}

type receiptValues struct {
	id      tftypes.Value
	version int
	groups  map[string]map[string]string
	label   tftypes.Value
}

func receiptResourceSchema(t *testing.T) (*awsSecurityGroupChangesReceiptResource, tftypes.Object, tfsdk.State) {
	t.Helper()
	r := &awsSecurityGroupChangesReceiptResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	objectType := schemaResp.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
	return r, objectType, tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objectType, nil)}
}

func receiptValue(objectType tftypes.Object, v receiptValues) tftypes.Value {
	changeSetsType := tftypes.Map{ElementType: tftypes.String}
	groups := map[string]tftypes.Value{}
	for groupID, changeSets := range v.groups {
		states := map[string]tftypes.Value{}
		for id, state := range changeSets {
			states[id] = tftypes.NewValue(tftypes.String, state)
		}
		groups[groupID] = tftypes.NewValue(changeSetsType, states)
	}
	return tftypes.NewValue(objectType, map[string]tftypes.Value{
		"id":               v.id,
		"cloud_account_id": tftypes.NewValue(tftypes.String, "123456789012"),
		"region":           tftypes.NewValue(tftypes.String, "us-east-1"),
		"version":          tftypes.NewValue(tftypes.String, versionOf(v.version)),
		"groups":           tftypes.NewValue(tftypes.Map{ElementType: changeSetsType}, groups),
		"label":            v.label,
	})
}

var unknownID = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

func narrowingWeb() receiptValues {
	return receiptValues{id: unknownID, version: 1, groups: map[string]map[string]string{"sg-0web": {"cs-1": "narrowing"}},
		label: tftypes.NewValue(tftypes.String, nil)}
}

// A receipt is posted as Xshield's contract describes it and signed as the gateway checks; it keeps the id it was
// created with when it reports something else, and destroying it asks Xshield to forget that id.
func TestAReceiptIsSentUnderOneIDAsTheContractSaysUntilItIsDestroyed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := newGatewayServer(t)
	r, objectType, absent := receiptResourceSchema(t)
	r.api = g.api()

	created := narrowingWeb()
	created.label = tftypes.NewValue(tftypes.String, "owner-web")
	createResp := resource.CreateResponse{State: absent}
	r.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, created)}}, &createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatal(createResp.Diagnostics)
	}
	var id string
	if diags := createResp.State.GetAttribute(ctx, path.Root("id"), &id); diags.HasError() || !regexp.MustCompile(`^`+receiptUUID+`$`).MatchString(id) {
		t.Fatalf("id %q (%v), want a version 4 UUID", id, diags)
	}

	updated := receiptValues{id: tftypes.NewValue(tftypes.String, id), version: 2,
		groups: map[string]map[string]string{"sg-0web": {"cs-2": "attaching", "cs-1": "restoring"}, "sg-0db": {}},
		label:  tftypes.NewValue(tftypes.String, nil)}
	updateResp := resource.UpdateResponse{State: createResp.State}
	r.Update(ctx, resource.UpdateRequest{Plan: tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, updated)}, State: createResp.State}, &updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatal(updateResp.Diagnostics)
	}
	var keptID string
	if updateResp.State.GetAttribute(ctx, path.Root("id"), &keptID); keptID != id {
		t.Errorf("id %q after an update, want %q", keptID, id)
	}

	var deleteResp resource.DeleteResponse
	r.Delete(ctx, resource.DeleteRequest{State: updateResp.State}, &deleteResp)
	if deleteResp.Diagnostics.HasError() {
		t.Fatal(deleteResp.Diagnostics)
	}

	want := []signedRequest{
		{http.MethodPost, receiptsPath, []byte(contractBody(id, "owner-web", 1, `{"id":"cs-1","state":"narrowing"}`))},
		{http.MethodPost, receiptsPath, []byte(fmt.Sprintf(`{"id":%q,"version":%q,"groups":[`+
			`{"groupId":"sg-0db","changeSets":[]},`+
			`{"groupId":"sg-0web","changeSets":[{"id":"cs-1","state":"restoring"},{"id":"cs-2","state":"attaching"}]}]}`, id, versionOf(2)))},
		{http.MethodDelete, receiptsPath + "/" + id, nil},
	}
	seen := g.requests()
	if len(seen) != len(want) {
		t.Fatalf("%d requests, want %d", len(seen), len(want))
	}
	for i := range want {
		if seen[i].method != want[i].method || seen[i].requestURI != want[i].requestURI || string(seen[i].body) != string(want[i].body) {
			t.Errorf("request %d:\n%s %s %s\nwant\n%s %s %s", i, seen[i].method, seen[i].requestURI, seen[i].body,
				want[i].method, want[i].requestURI, want[i].body)
		}
	}
	if err := expectNoWorkspaceOrQuery(seen); err != nil {
		t.Error(err)
	}
}

type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection reset by peer")
}

func apiAnswering(t *testing.T, status int, body string) cloudSnapshotAPI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return cloudSnapshotAPI{client: sdk.New(sdk.WithServerURL(srv.URL), sdk.WithClient(srv.Client()),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", testKeyPEM(t))),
		sdk.WithRetryConfig(retry.Config{Strategy: "none"}))}
}

// A receipt Xshield refused was not recorded, so the next plan creates it again. One whose answer never came may have
// been: it stays in state, where Terraform marks it tainted, so the next apply deletes that id before sending a new one.
func TestACreatedReceiptStaysInStateOnlyWhenXshieldMayHoldIt(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		api     func(t *testing.T) cloudSnapshotAPI
		inState bool
	}{
		"refused": {func(t *testing.T) cloudSnapshotAPI {
			return apiAnswering(t, http.StatusBadRequest, `{"message":"malformed customer group changes receipt"}`)
		}, false},
		"unauthorized": {func(t *testing.T) cloudSnapshotAPI { return apiAnswering(t, http.StatusUnauthorized, gatewayRefusal) }, false},
		"failed in Xshield": {func(t *testing.T) cloudSnapshotAPI {
			return apiAnswering(t, http.StatusInternalServerError, `{"message":"internal error"}`)
		}, true},
		"no answer": {func(t *testing.T) cloudSnapshotAPI {
			return cloudSnapshotAPI{client: sdk.New(sdk.WithServerURL("http://127.0.0.1:1"), sdk.WithClient(&http.Client{Transport: unreachable{}}),
				sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", testKeyPEM(t))),
				sdk.WithRetryConfig(retry.Config{Strategy: "none"}))}
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, objectType, absent := receiptResourceSchema(t)
			r.api = test.api(t)
			resp := resource.CreateResponse{State: absent}
			r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, narrowingWeb())}}, &resp)
			if !resp.Diagnostics.HasError() {
				t.Fatal("a receipt Xshield did not accept was created without an error")
			}
			if detail := resp.Diagnostics.Errors()[0].Detail(); !strings.Contains(detail, "The group's rules are applied. Apply again") {
				t.Errorf("the error does not say the rules are applied and to apply again:\n%s", detail)
			}
			if inState := !resp.State.Raw.IsNull(); inState != test.inState {
				t.Errorf("kept in state: %v, want %v", inState, test.inState)
			}
		})
	}
}

// Xshield refuses a receipt listing a narrowing change set for an account and region with nothing published: the
// changes the plan read are gone, so sending it again cannot help, and the error says to plan again.
func TestAReceiptForChangesNoLongerPublishedSaysToPlanAgainWithoutRetrying(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, xshieldNotPublished)
	}))
	t.Cleanup(srv.Close)
	r, objectType, absent := receiptResourceSchema(t)
	r.api = cloudSnapshotAPI{client: sdk.New(sdk.WithServerURL(srv.URL), sdk.WithClient(srv.Client()),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", testKeyPEM(t))))}

	resp := resource.CreateResponse{State: absent}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, narrowingWeb())}}, &resp)
	if !resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Fatalf("error %v and state %v, want an error and no receipt in state", resp.Diagnostics, resp.State.Raw)
	}
	want := "The group's rules are applied, but Xshield has no published snapshot for this account and region, so the changes " +
		"this plan read no longer exist: run a new plan and apply it."
	if detail := resp.Diagnostics.Errors()[0].Detail(); !strings.HasSuffix(detail, want) {
		t.Errorf("detail:\n%s\nwant it to end:\n%s", detail, want)
	}
	if posts != 1 {
		t.Errorf("posted %d times, want once", posts)
	}

	other := apiAnswering(t, http.StatusNotFound, "404 page not found")
	r.api = other
	resp = resource.CreateResponse{State: absent}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, narrowingWeb())}}, &resp)
	if detail := resp.Diagnostics.Errors()[0].Detail(); strings.Contains(detail, "no published snapshot") {
		t.Errorf("a 404 Xshield did not code as nothing published says nothing is published:\n%s", detail)
	}
}

// An update Xshield does not accept leaves the state as it was, so the next plan sends it again under the same id.
func TestAnUpdateXshieldRefusesKeepsWhatWasLastSent(t *testing.T) {
	t.Parallel()
	r, objectType, absent := receiptResourceSchema(t)
	r.api = apiAnswering(t, http.StatusBadRequest, `{"message":"malformed customer group changes receipt"}`)
	sent := narrowingWeb()
	sent.id = tftypes.NewValue(tftypes.String, "0f8fad5b-d9cb-469f-a165-70867728950e")
	planned := sent
	planned.version = 2
	prior := tfsdk.State{Schema: absent.Schema, Raw: receiptValue(objectType, sent)}

	resp := resource.UpdateResponse{State: prior}
	r.Update(context.Background(), resource.UpdateRequest{Plan: tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, planned)}, State: prior}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("an update Xshield refused succeeded")
	}
	if !resp.State.Raw.Equal(prior.Raw) {
		t.Errorf("state %v after a refused update, want the receipt last sent %v", resp.State.Raw, prior.Raw)
	}
}

// Destroying a receipt asks Xshield to forget it. Xshield answers 204 for any id, and 404 where it holds nothing for
// the account and region, so either is done; any other answer leaves a revert waiting on the receipt.
func TestADestroyedReceiptIsForgottenOrSaysWhyNot(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		status  int
		wantErr bool
	}{
		"forgotten":         {http.StatusNoContent, false},
		"not known there":   {http.StatusNotFound, false},
		"refused":           {http.StatusForbidden, true},
		"failed in Xshield": {http.StatusInternalServerError, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, objectType, absent := receiptResourceSchema(t)
			r.api = apiAnswering(t, test.status, `{"message":"no"}`)
			stored := narrowingWeb()
			stored.id = tftypes.NewValue(tftypes.String, "0f8fad5b-d9cb-469f-a165-70867728950e")
			var resp resource.DeleteResponse
			r.Delete(context.Background(), resource.DeleteRequest{State: tfsdk.State{Schema: absent.Schema, Raw: receiptValue(objectType, stored)}}, &resp)
			if resp.Diagnostics.HasError() != test.wantErr {
				t.Fatalf("error %v, want %v: %v", resp.Diagnostics.HasError(), test.wantErr, resp.Diagnostics)
			}
			if test.wantErr && !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "keeps the access") {
				t.Errorf("the error does not say a revert keeps waiting:\n%s", resp.Diagnostics.Errors()[0].Detail())
			}
		})
	}
}

// A receipt is imported by the account, the region and the id a notice names, so it can be destroyed.
func TestAReceiptIsImportedByAccountRegionAndID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, _, absent := receiptResourceSchema(t)
	resp := resource.ImportStateResponse{State: absent}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "123456789012/us-east-1/0f8fad5b-d9cb-469f-a165-70867728950e"}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	for attribute, want := range map[string]string{"id": "0f8fad5b-d9cb-469f-a165-70867728950e", "cloud_account_id": "123456789012", "region": "us-east-1"} {
		var got string
		if resp.State.GetAttribute(ctx, path.Root(attribute), &got); got != want {
			t.Errorf("%s %q, want %q", attribute, got, want)
		}
	}

	for _, id := range []string{"0f8fad5b-d9cb-469f-a165-70867728950e", "123456789012/0f8fad5b-d9cb-469f-a165-70867728950e",
		"123456789012/us-east-1/receipt-1", "123456789012/us-east-1/0f8fad5b-d9cb-469f-a165-70867728950e/x",
		"/us-east-1/0f8fad5b-d9cb-469f-a165-70867728950e", "123456789012//0f8fad5b-d9cb-469f-a165-70867728950e",
		"123456789012/us-east-1/0F8FAD5B-D9CB-469F-A165-70867728950E"} {
		_, _, absent := receiptResourceSchema(t)
		resp := resource.ImportStateResponse{State: absent}
		r.ImportState(ctx, resource.ImportStateRequest{ID: id}, &resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("imported %q", id)
		}
	}
}

// An unset label plans as the run's workspace name where HCP Terraform gives one that fits, and as null otherwise.
func TestAnUnsetLabelIsTheWorkspaceName(t *testing.T) {
	for name, test := range map[string]struct {
		workspace string
		config    types.String
		want      types.String
		warns     bool
	}{
		"in HCP Terraform":            {"owner-web", types.StringNull(), types.StringValue("owner-web"), false},
		"elsewhere":                   {"", types.StringNull(), types.StringNull(), false},
		"a name that cannot be shown": {"owner web; drop", types.StringNull(), types.StringNull(), true},
		"set in the configuration":    {"owner-web", types.StringValue("orders"), types.StringValue("orders"), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TFC_WORKSPACE_NAME", test.workspace)
			_, objectType, absent := receiptResourceSchema(t)
			planValue := types.StringUnknown()
			if !test.config.IsNull() {
				planValue = test.config
			}
			req := planmodifier.StringRequest{
				Path:        path.Root("label"),
				ConfigValue: test.config,
				Plan:        tfsdk.Plan{Schema: absent.Schema, Raw: receiptValue(objectType, narrowingWeb())},
				PlanValue:   planValue,
				StateValue:  types.StringNull(),
			}
			resp := planmodifier.StringResponse{PlanValue: req.PlanValue}
			workspaceNameLabel{}.PlanModifyString(context.Background(), req, &resp)
			if !resp.PlanValue.Equal(test.want) || (resp.Diagnostics.WarningsCount() > 0) != test.warns {
				t.Errorf("label %v with %d warning(s), want %v and a warning %v", resp.PlanValue, resp.Diagnostics.WarningsCount(), test.want, test.warns)
			}
		})
	}
}

const ownerConfig = `
data "xshield_aws_security_group_rules" "web" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
  vpc_id           = "vpc-0web"
  group_name       = "web"
}

resource "xshield_aws_security_group_changes_receipt" "web" {
  cloud_account_id = data.xshield_aws_security_group_rules.web.cloud_account_id
  region           = data.xshield_aws_security_group_rules.web.region
  version          = data.xshield_aws_security_group_rules.web.version
  groups = {
    (data.xshield_aws_security_group_rules.web.security_group_id) = data.xshield_aws_security_group_rules.web.change_sets
  }
}
`

// expectReceiptPosted checks the last request was the receipt for the id in state, as Xshield's contract describes it.
func expectReceiptPosted(g *gatewayServer, version int, changeSets string) tfresource.TestCheckFunc {
	return func(s *terraform.State) error {
		seen := g.requests()
		last := seen[len(seen)-1]
		want := contractBody(s.RootModule().Resources[changesReceiptAddress].Primary.ID, "owner-web", version, changeSets)
		if last.method != http.MethodPost || last.requestURI != receiptsPath || string(last.body) != want {
			return fmt.Errorf("last request %s %s %s, want POST %s %s", last.method, last.requestURI, last.body, receiptsPath, want)
		}
		return nil
	}
}

// changesServedBeforeApply serves other changes once the plan is saved, as a revert requested after it does.
type changesServedBeforeApply struct {
	g       *gatewayServer
	changes string
	at      *int
}

func (c changesServedBeforeApply) CheckPlan(ctx context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	*c.at = len(c.g.requests())
	c.g.serve(c.changes)
}

// A workspace reports the changes its rules came from, under one id for the receipt's life, from the values its plan
// holds: a plan saved before a revert and applied after it reports the changes as they were, and applying again
// reports them as they are.
func TestAccChangesReceiptReportsWhatItsPlanRead(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("TFC_WORKSPACE_NAME", "owner-web")
	t.Setenv("TFC_WORKSPACE_ID", "ws-AbC123")
	g := newGatewayServer(t)
	config := g.providerBlock() + ownerConfig
	sameID := statecheck.CompareValue(compare.ValuesSame())
	var createdID string
	savedPlanAppliedAt := 0

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				PreConfig: func() { g.serve(servedChanges(1, `{"id":"cs-1","state":"narrowing","moves":[]}`)) },
				Config:    config,
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(changesReceiptAddress, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(changesReceiptAddress, tfjsonpath.New("id"), knownvalue.StringRegexp(regexp.MustCompile(`^`+receiptUUID+`$`))),
					statecheck.ExpectKnownValue(changesReceiptAddress, tfjsonpath.New("label"), knownvalue.StringExact("owner-web")),
				},
				Check: tfresource.ComposeTestCheckFunc(
					expectReceiptPosted(g, 1, `{"id":"cs-1","state":"narrowing"}`),
					func(s *terraform.State) error {
						createdID = s.RootModule().Resources[changesReceiptAddress].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					g.serve(servedChanges(2, `{"id":"cs-2","state":"attaching","moves":[]},{"id":"cs-1","state":"restoring","moves":[]}`))
				},
				Config: config,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(changesReceiptAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{sameID.AddStateValue(changesReceiptAddress, tfjsonpath.New("id"))},
				Check:             expectReceiptPosted(g, 2, `{"id":"cs-1","state":"restoring"},{"id":"cs-2","state":"attaching"}`),
			},
			{
				PreConfig: func() { g.serve(servedChanges(3, `{"id":"cs-2","state":"narrowing","moves":[]}`)) },
				Config:    config,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(changesReceiptAddress, plancheck.ResourceActionUpdate),
					changesServedBeforeApply{g: g, changes: servedChanges(4, `{"id":"cs-2","state":"restoring","moves":[]}`), at: &savedPlanAppliedAt},
				}},
				ExpectNonEmptyPlan: true,
				ConfigStateChecks:  []statecheck.StateCheck{sameID.AddStateValue(changesReceiptAddress, tfjsonpath.New("id"))},
				Check: tfresource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						if applied := g.requests()[savedPlanAppliedAt:]; len(applied) != 1 {
							return fmt.Errorf("the saved plan's apply sent %d requests, want only the receipt", len(applied))
						}
						return nil
					},
					expectReceiptPosted(g, 3, `{"id":"cs-2","state":"narrowing"}`),
				),
			},
			{
				Config:            config,
				ConfigStateChecks: []statecheck.StateCheck{sameID.AddStateValue(changesReceiptAddress, tfjsonpath.New("id"))},
				Check:             expectReceiptPosted(g, 4, `{"id":"cs-2","state":"restoring"}`),
			},
			{
				ResourceName: changesReceiptAddress,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return "123456789012/us-east-1/" + s.RootModule().Resources[changesReceiptAddress].Primary.ID, nil
				},
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"version", "groups", "label"},
			},
		},
		CheckDestroy: func(s *terraform.State) error {
			seen := g.requests()
			if last := seen[len(seen)-1]; last.method != http.MethodDelete || last.requestURI != receiptsPath+"/"+createdID {
				return fmt.Errorf("last request %s %s, want DELETE %s/%s", last.method, last.requestURI, receiptsPath, createdID)
			}
			return expectNoWorkspaceOrQuery(seen)
		},
	})
}

// A receipt left behind by a workspace deleted without being destroyed is imported into any configuration and
// destroyed, as the guide says: that sends only the DELETE of the imported id, never a receipt.
func TestAccAnOrphanedReceiptIsImportedAndDestroyed(t *testing.T) {
	clearXshieldEnv(t)
	g := newGatewayServer(t)
	const orphanID = "0f8fad5b-d9cb-469f-a165-70867728950e"

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				Config: g.providerBlock() + `
resource "xshield_aws_security_group_changes_receipt" "orphan" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
  version          = "orphan"
  groups           = {}
}
`,
				ResourceName:       "xshield_aws_security_group_changes_receipt.orphan",
				ImportState:        true,
				ImportStateId:      "123456789012/us-east-1/" + orphanID,
				ImportStatePersist: true,
			},
		},
		CheckDestroy: func(s *terraform.State) error {
			seen := g.requests()
			if len(seen) != 1 || seen[0].method != http.MethodDelete || seen[0].requestURI != receiptsPath+"/"+orphanID {
				return fmt.Errorf("requests %v, want only DELETE %s/%s", seen, receiptsPath, orphanID)
			}
			return nil
		},
	})
}

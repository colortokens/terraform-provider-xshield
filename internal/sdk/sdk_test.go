package sdk_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

// The signing hook needs a real RSA key. Generating one per test dominates the
// runtime, so build it once and share the immutable PEM across tests.
var (
	testKeyOnce sync.Once
	testKeyPEM  string
)

func signingConfig(t *testing.T) shared.ConfigurationProvider {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
	})
	return shared.NewDirectConfigProvider("tenancy", "user", "fingerprint", testKeyPEM)
}

// capture records what the SDK actually put on the wire.
type capture struct {
	method string
	path   string
	query  string
	body   map[string]any
	raw    string
}

// newTestClient returns an SDK bound to a server that records one request and
// replies with the given status and body.
func newTestClient(t *testing.T, status int, responseBody string) (*sdk.Xshield, *capture) {
	t.Helper()
	got := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		raw, _ := io.ReadAll(r.Body)
		got.raw = string(raw)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &got.body)
		}
		if responseBody != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		if responseBody != "" {
			_, _ = io.WriteString(w, responseBody)
		}
	}))
	t.Cleanup(srv.Close)

	return sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(signingConfig(t)),
		sdk.WithClient(srv.Client()),
	), got
}

func TestConfigureZeroTrustSendsDeploymentState(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusAccepted, `"accepted"`)

	res, err := client.Assets.ConfigureZeroTrust(context.Background(), operations.ConfigureZeroTrustRequest{
		AssetID: "a1b2c3d4-0000-0000-0000-000000000000",
		AssetStateTransitionInput: shared.AssetStateTransitionInput{
			InboundToDeploymentState:  shared.AssetDeploymentStateEnabled.ToPointer(),
			OutboundToDeploymentState: shared.AssetDeploymentStateDisabled.ToPointer(),
		},
	})
	if err != nil {
		t.Fatalf("ConfigureZeroTrust: %v", err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", res.StatusCode)
	}
	if want := "/api/assets/a1b2c3d4-0000-0000-0000-000000000000/zerotrust"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if got.method != http.MethodPut {
		t.Errorf("method = %q, want PUT", got.method)
	}
	// The backend renamed these fields and narrowed the vocabulary; the old
	// inboundToState / "secure-internet-ports" body is rejected outright.
	if v := got.body["inboundToDeploymentState"]; v != "enabled" {
		t.Errorf("inboundToDeploymentState = %v, want \"enabled\"", v)
	}
	if v := got.body["outboundToDeploymentState"]; v != "disabled" {
		t.Errorf("outboundToDeploymentState = %v, want \"disabled\"", v)
	}
	if _, stale := got.body["inboundToState"]; stale {
		t.Errorf("request still carries the removed inboundToState field: %s", got.raw)
	}
}

func TestConfigureZeroTrustNotModifiedHasNoBody(t *testing.T) {
	t.Parallel()
	// The backend answers 304 with no body when the asset is already in the
	// requested state. Decoding a body here used to fail the whole call.
	client, _ := newTestClient(t, http.StatusNotModified, "")

	res, err := client.Assets.ConfigureZeroTrust(context.Background(), operations.ConfigureZeroTrustRequest{
		AssetID:                   "a1b2c3d4-0000-0000-0000-000000000000",
		AssetStateTransitionInput: shared.AssetStateTransitionInput{InboundToDeploymentState: shared.AssetDeploymentStateEnabled.ToPointer()},
	})
	if err != nil {
		t.Fatalf("ConfigureZeroTrust: %v", err)
	}
	if res.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", res.StatusCode)
	}
}

func TestDeployPortsSendsDeploymentPlan(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusOK,
		`{"reviewedPorts":[{"listenPort":"443","listenPortProtocol":"TCP","affectedAssetsCount":3}],"unreviewedPorts":[]}`)

	res, err := client.Policy.DeployPorts(context.Background(), shared.PortDeploymentInput{
		DeploymentCriteria: shared.PortEnforceModeInput{
			Criteria:  "application = 'payroll'",
			Direction: sdk.String("inbound"),
		},
		DeploymentPlan: shared.DeploymentPlan{
			Reviewed: map[string]shared.DeploymentConfig{
				"TCP:443": {DeploymentMode: shared.DeploymentModeEnforce, TargetAssets: shared.TargetAssetsAll.ToPointer()},
			},
			Unreviewed: map[string]shared.DeploymentConfig{
				"*": {DeploymentMode: shared.DeploymentModeTest},
			},
		},
	})
	if err != nil {
		t.Fatalf("DeployPorts: %v", err)
	}
	if got.path != "/api/policy/actions/deploy" || got.method != http.MethodPost {
		t.Fatalf("request = %s %s, want POST /api/policy/actions/deploy", got.method, got.path)
	}

	criteria := got.body["deploymentCriteria"].(map[string]any)
	if criteria["criteria"] != "application = 'payroll'" {
		t.Errorf("criteria = %v", criteria["criteria"])
	}
	plan := got.body["deploymentPlan"].(map[string]any)
	reviewed := plan["reviewed"].(map[string]any)["TCP:443"].(map[string]any)
	if reviewed["deploymentMode"] != "enforce" || reviewed["targetAssets"] != "all" {
		t.Errorf("reviewed plan = %v, want enforce/all", reviewed)
	}
	// Both wildcard keys present means the backend treats this as a whole-asset
	// deploy rather than micro-deployment.
	if _, ok := plan["unreviewed"].(map[string]any)["*"]; !ok {
		t.Errorf("unreviewed plan missing the \"*\" key: %s", got.raw)
	}

	if res.DeploymentPorts == nil || len(res.DeploymentPorts.ReviewedPorts) != 1 {
		t.Fatalf("response not decoded: %+v", res.DeploymentPorts)
	}
	if p := res.DeploymentPorts.ReviewedPorts[0]; p.GetListenPort() == nil || *p.GetListenPort() != "443" {
		t.Errorf("listenPort = %v, want 443", p.GetListenPort())
	}
}

func TestDeployPortsNotModified(t *testing.T) {
	t.Parallel()
	client, _ := newTestClient(t, http.StatusNotModified, "")

	res, err := client.Policy.DeployPorts(context.Background(), shared.PortDeploymentInput{
		DeploymentCriteria: shared.PortEnforceModeInput{Criteria: "*"},
	})
	if err != nil {
		t.Fatalf("DeployPorts: %v", err)
	}
	if res.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", res.StatusCode)
	}
}

func TestRefreshAssetPolicyConfigurationUsesRenamedPath(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusAccepted, "")

	// The route was /refresh-progressive before the backend renamed it.
	_, err := client.Tagbasedpolicies.RefreshAssetPolicyConfiguration(context.Background(),
		operations.RefreshAssetPolicyConfigurationRequest{TagbasedpolicyID: "seg-1"})
	if err != nil {
		t.Fatalf("RefreshAssetPolicyConfiguration: %v", err)
	}
	if want := "/api/tagbasedpolicies/seg-1/refresh-assetpolicy"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
}

func TestGetTagBasedPolicyAssetsDecodesMembership(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusOK, `{"items":["asset-1","asset-2"]}`)

	res, err := client.Tagbasedpolicies.GetTagBasedPolicyAssets(context.Background(),
		operations.GetTagBasedPolicyAssetsRequest{TagbasedpolicyID: "seg-1"})
	if err != nil {
		t.Fatalf("GetTagBasedPolicyAssets: %v", err)
	}
	if want := "/api/tagbasedpolicies/seg-1/assets"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if res.MembershipList == nil || len(res.MembershipList.Items) != 2 {
		t.Fatalf("membership not decoded: %+v", res.MembershipList)
	}
}

func TestListAssetsForPortSendsQueryAndCriteria(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusOK, `{"items":[{"assetId":"a1","listenPortEnforced":"allow-any"}]}`)

	res, err := client.Policy.ListAssetsForPort(context.Background(), operations.ListAssetsForPortRequest{
		UnreviewedPort: sdk.Bool(true),
		AssetsSearchInput: shared.AssetsSearchInput{
			Criteria: "*",
			Port:     sdk.String("443"),
			Protocol: sdk.String("TCP"),
		},
	})
	if err != nil {
		t.Fatalf("ListAssetsForPort: %v", err)
	}
	if got.path != "/api/policy/affectedassets/actions/search" {
		t.Errorf("path = %q", got.path)
	}
	if got.query != "unreviewedPort=true" {
		t.Errorf("query = %q, want unreviewedPort=true", got.query)
	}
	if got.body["port"] != "443" {
		t.Errorf("port = %v, want 443", got.body["port"])
	}
	if res.AssetList == nil || len(res.AssetList.Items) != 1 {
		t.Fatalf("asset list not decoded: %+v", res.AssetList)
	}
}

func TestSummarizeFieldDecodesFacet(t *testing.T) {
	t.Parallel()
	// The handler returns the facet under a capitalised key because the Go
	// struct field carries no JSON tag.
	client, got := newTestClient(t, http.StatusOK,
		`{"Facet":{"field":"environment","hasMore":false,"values":{"prod":12,"dev":3}}}`)

	res, err := client.Metadata.SummarizeField(context.Background(), shared.SummarizeField{
		Criteria:   "*",
		FacetField: "environment",
		Scope:      sdk.String("asset"),
	})
	if err != nil {
		t.Fatalf("SummarizeField: %v", err)
	}
	if got.path != "/api/fields/actions/summarize" {
		t.Errorf("path = %q", got.path)
	}
	if res.SummarizeFieldResults == nil || res.SummarizeFieldResults.Facet == nil {
		t.Fatalf("facet not decoded: %+v", res.SummarizeFieldResults)
	}
	if v := res.SummarizeFieldResults.Facet.Values["prod"]; v != 12 {
		t.Errorf("values[prod] = %d, want 12", v)
	}
}

func TestGetWorkRequestDecodesStatus(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusOK,
		`{"id":"w-1","status":"InProgress","action":"AssetUpdated","resourceId":"a1","subject":"user"}`)

	res, err := client.Workrequests.GetWorkRequest(context.Background(),
		operations.GetWorkRequestRequest{WorkID: "w-1"})
	if err != nil {
		t.Fatalf("GetWorkRequest: %v", err)
	}
	if got.path != "/api/workRequests/w-1" {
		t.Errorf("path = %q", got.path)
	}
	if res.WorkrequestWorkRequest == nil {
		t.Fatalf("work request not decoded")
	}
	if s := res.WorkrequestWorkRequest.Status; s == nil || *s != shared.WorkrequestChangeStatusInProgress {
		t.Errorf("status = %v, want InProgress", s)
	}
}

func TestBulkDeployFirewallConfiguration(t *testing.T) {
	t.Parallel()
	client, got := newTestClient(t, http.StatusAccepted, `"accepted"`)

	res, err := client.Assets.BulkDeployFirewallConfiguration(context.Background(),
		shared.SearchInput{Criteria: "environment = 'prod'"})
	if err != nil {
		t.Fatalf("BulkDeployFirewallConfiguration: %v", err)
	}
	if got.path != "/api/assets/firewallconfiguration/deploy" || got.method != http.MethodPost {
		t.Fatalf("request = %s %s", got.method, got.path)
	}
	if got.body["criteria"] != "environment = 'prod'" {
		t.Errorf("criteria = %v", got.body["criteria"])
	}
	if res.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", res.StatusCode)
	}
}

func TestDeleteFromTemplateAcceptsAccepted(t *testing.T) {
	t.Parallel()
	// The deduct is applied asynchronously and the handler answers 202, but the
	// document listed only 204, so an ordinary success surfaced as an SDK error
	// and the provider had to match on the error text to carry on.
	client, got := newTestClient(t, http.StatusAccepted, "")

	res, err := client.Templates.DeleteFromTemplate(context.Background(), operations.DeleteFromTemplateRequest{
		Templateid: "tpl-1",
		APITemplatePayloadHashes: shared.APITemplatePayloadHashes{
			Ports: []string{"lp-hash"},
			Paths: []string{"channel-hash"},
		},
	})
	if err != nil {
		t.Fatalf("DeleteFromTemplate returned an error for a 202: %v", err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", res.StatusCode)
	}
	if got.path != "/api/v2/templates/tpl-1/deduct" || got.method != http.MethodDelete {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if ports, ok := got.body["ports"].([]any); !ok || len(ports) != 1 {
		t.Errorf("ports not sent: %s", got.raw)
	}
}

func TestDeleteFromTemplateStillAcceptsNoContent(t *testing.T) {
	t.Parallel()
	client, _ := newTestClient(t, http.StatusNoContent, "")

	res, err := client.Templates.DeleteFromTemplate(context.Background(), operations.DeleteFromTemplateRequest{
		Templateid:               "tpl-1",
		APITemplatePayloadHashes: shared.APITemplatePayloadHashes{Ports: []string{"lp-hash"}},
	})
	if err != nil {
		t.Fatalf("DeleteFromTemplate: %v", err)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", res.StatusCode)
	}
}

func TestSearchInputNestsPagination(t *testing.T) {
	t.Parallel()
	// The backend reads limit, offset and sort from a "pagination" object. Sending
	// them at the top level, as this SDK used to, left every search on the default
	// page of 100 rows with the sort ignored, and said nothing about it.
	client, got := newTestClient(t, http.StatusOK, `{"items":[]}`)

	_, err := client.Assets.ListAssets(context.Background(), operations.ListAssetsRequest{
		ComputeTotal: sdk.String("true"),
		SearchInput: shared.SearchInput{
			Criteria: "*",
			Pagination: &shared.PaginationConfig{
				Limit:  sdk.Int64(1000),
				Offset: sdk.Int64(2000),
				Sort:   []shared.OrderBy{{Field: sdk.String("assetId"), Order: shared.SortOrderAsc.ToPointer()}},
			},
		},
	}, operations.WithAcceptHeaderOverride(operations.AcceptHeaderEnumApplicationJson))
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}

	if _, flat := got.body["limit"]; flat {
		t.Errorf("limit is still at the top level, where the backend ignores it: %s", got.raw)
	}
	pagination, ok := got.body["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("no pagination object in the request body: %s", got.raw)
	}
	if pagination["limit"] != float64(1000) || pagination["offset"] != float64(2000) {
		t.Errorf("pagination = %v, want limit 1000 and offset 2000", pagination)
	}
	sort, ok := pagination["sort"].([]any)
	if !ok || len(sort) != 1 {
		t.Fatalf("sort = %v", pagination["sort"])
	}
	if entry := sort[0].(map[string]any); entry["field"] != "assetId" || entry["order"] != "Asc" {
		t.Errorf("sort entry = %v, want assetId ascending", entry)
	}
	if got.query != "computeTotal=true" {
		t.Errorf("query = %q, want computeTotal=true so the response carries a total", got.query)
	}
}

func TestListFieldsDecodesTheColumnCatalogue(t *testing.T) {
	t.Parallel()
	// GET /api/fields answers with a "columns" object. The route's swagger
	// annotation claims a typeahead shape instead, so the generated decode
	// produced an empty catalogue against a perfectly good response.
	client, got := newTestClient(t, http.StatusOK, `{"columns":{
		"environment":{"internalName":"environment","displayName":"Environment","coreTag":true,"facetable":true,
			"dataType":"String","listOfValues":false},
		"assettype":{"internalName":"assettype","displayName":"Asset Type","listOfValues":true,
			"values":[{"display":"server","internal":1},{"display":"endpoint","internal":2}]}
	}}`)

	res, err := client.Metadata.ListFields(context.Background(),
		operations.ListFieldsRequest{Scope: sdk.String("asset")})
	if err != nil {
		t.Fatalf("ListFields: %v", err)
	}
	if got.path != "/api/fields" || got.query != "scope=asset" {
		t.Errorf("request = %s?%s", got.path, got.query)
	}
	if res.MetadataResponse == nil || len(res.MetadataResponse.Columns) != 2 {
		t.Fatalf("catalogue not decoded: %+v", res.MetadataResponse)
	}
	env := res.MetadataResponse.Columns["environment"]
	if env.CoreTag == nil || !*env.CoreTag {
		t.Error("environment should be reported as a core tag")
	}
	assetType := res.MetadataResponse.Columns["assettype"]
	if len(assetType.Values) != 2 || assetType.Values[0].Display == nil || *assetType.Values[0].Display != "server" {
		t.Errorf("list-of-values not decoded: %+v", assetType.Values)
	}
}

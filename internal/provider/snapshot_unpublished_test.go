package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const (
	xshieldNotPublished = `{"status":404,"code":"notPublished","message":"no snapshot published for this account and region"}`
	xshieldNotApplied   = `{"status":409,"code":"notApplied","message":"nothing has been applied yet, so there is no state to drift from"}`
	xshieldNotObserved  = `{"status":404,"code":"notObserved","message":"no cloud observation recorded yet"}`
)

type cannedResponse struct {
	status int
	body   string
}

// newRoutedSnapshotAPI answers each path suffix as given, and 404 "page not found" for any other path, as a missing route does.
func newRoutedSnapshotAPI(t *testing.T, routes map[string]cannedResponse) (cloudSnapshotAPI, *[]string) {
	t.Helper()
	var mu sync.Mutex
	requested := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		for suffix, res := range routes {
			if strings.HasSuffix(r.URL.Path, suffix) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(res.status)
				_, _ = io.WriteString(w, res.body)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "404 page not found")
	}))
	t.Cleanup(srv.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	client := sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", keyPEM)),
		sdk.WithClient(srv.Client()),
	)
	return cloudSnapshotAPI{client: client}, &requested
}

// readDataSource runs the data source's own Read with the given arguments and every other attribute null.
func readDataSource(t *testing.T, ds datasource.DataSource, args map[string]tftypes.Value, out any) (ok bool, errors string) {
	t.Helper()
	ctx := context.Background()
	var schemaResp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	objectType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, attrType := range objectType.AttributeTypes {
		values[name] = tftypes.NewValue(attrType, nil)
		if v, given := args[name]; given {
			values[name] = v
		}
	}
	req := datasource.ReadRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objectType, values)}}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objectType, nil)}}
	ds.Read(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		var sb strings.Builder
		for _, d := range resp.Diagnostics.Errors() {
			sb.WriteString(d.Summary() + ": " + d.Detail() + "\n")
		}
		return false, sb.String()
	}
	if diags := resp.State.Get(ctx, out); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	return true, ""
}

func pointArgs() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"cloud_account_id": tftypes.NewValue(tftypes.String, "123456789012"),
		"region":           tftypes.NewValue(tftypes.String, "us-east-1"),
	}
}

func TestNothingPublishedReadsAsAnEmptySnapshotWithoutFetchingAVersion(t *testing.T) {
	t.Parallel()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/expected": {http.StatusNotFound, xshieldNotPublished}})
	var m EnforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &EnforcementSnapshotDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatalf("an account with nothing published must plan, not fail: %s", errs)
	}
	if m.Published.ValueBool() || !m.Version.IsNull() || !m.ContentHash.IsNull() {
		t.Errorf("published %v version %v hash %v, want false, null, null", m.Published, m.Version, m.ContentHash)
	}
	if len(m.SecurityGroups)+len(m.IngressRules)+len(m.EgressRules)+len(m.InterfaceAttachments)+len(m.Directory)+len(m.Assets)+len(m.Withdrawing) != 0 {
		t.Errorf("an unpublished snapshot must hold nothing to create: %+v", m)
	}
	if len(*requested) != 1 {
		t.Errorf("requested %v, want only the expected version", *requested)
	}
}

func TestPublishedSnapshotSaysSo(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/expected":    {http.StatusOK, `{"version":42,"contentHash":"sha256:x"}`},
		"/versions/42": {http.StatusOK, readTestdata(t, "snapshot.json")},
	})
	var m EnforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &EnforcementSnapshotDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatal(errs)
	}
	if !m.Published.ValueBool() || m.Version.ValueInt64() != 42 || len(m.SecurityGroups) == 0 {
		t.Errorf("published %v version %v groups %d, want true, 42 and the snapshot's groups", m.Published, m.Version, len(m.SecurityGroups))
	}
}

// Only Xshield's own "nothing published" may plan empty: read as empty, any
// other 404 would plan the removal of every group a workspace applied.
func TestAnyOtherFailureToReadTheSnapshotFailsThePlan(t *testing.T) {
	t.Parallel()
	for name, routes := range map[string]map[string]cannedResponse{
		"missing route":            {},
		"proxy 404 without a code": {"/expected": {http.StatusNotFound, `{"message":"no Route matched with those values"}`}},
		"404 with another code":    {"/expected": {http.StatusNotFound, `{"status":404,"code":"notObserved","message":"x"}`}},
		"forbidden":                {"/expected": {http.StatusForbidden, `{"status":403,"message":"cloud snapshots are served to users whose role covers every asset"}`}},
		"unauthorized":             {"/expected": {http.StatusUnauthorized, `{"message":"Unauthorized"}`}},
		"not published, but 403":   {"/expected": {http.StatusForbidden, `{"status":403,"code":"notPublished","message":"x"}`}},
		"expected version gone":    {"/expected": {http.StatusOK, `{"version":42,"contentHash":"sha256:x"}`}},
	} {
		api, _ := newRoutedSnapshotAPI(t, routes)
		var m EnforcementSnapshotDataSourceModel
		if ok, _ := readDataSource(t, &EnforcementSnapshotDataSource{api: api}, pointArgs(), &m); ok {
			t.Errorf("%s: the plan went ahead with %+v", name, m)
		}
	}
}

func TestPinnedVersionMustExistEvenWhenNothingIsPublished(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/expected":   {http.StatusNotFound, xshieldNotPublished},
		"/versions/7": {http.StatusNotFound, `{"status":404,"message":"unknown snapshot version","details":{"retained":20}}`},
	})
	args := pointArgs()
	args["version"] = tftypes.NewValue(tftypes.Number, 7)
	var m EnforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &EnforcementSnapshotDataSource{api: api}, args, &m); ok || !strings.Contains(errs, "version 7") {
		t.Errorf("a pin to a version Xshield does not hold must fail, naming it; got ok=%v %q", ok, errs)
	}
}

func TestDeclaredRulesComeBackUnchangedWhenNothingIsPublished(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/expected": {http.StatusNotFound, xshieldNotPublished}})
	ruleType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"ip_protocol": tftypes.String, "from_port": tftypes.Number, "to_port": tftypes.Number,
		"cidr_ipv4": tftypes.String, "cidr_ipv6": tftypes.String, "prefix_list_id": tftypes.String,
		"referenced_security_group_id": tftypes.String, "description": tftypes.String, "tags": tftypes.Map{ElementType: tftypes.String},
	}}
	rule := tftypes.NewValue(ruleType, map[string]tftypes.Value{
		"ip_protocol": tftypes.NewValue(tftypes.String, "tcp"), "from_port": tftypes.NewValue(tftypes.Number, 443),
		"to_port": tftypes.NewValue(tftypes.Number, 443), "cidr_ipv4": tftypes.NewValue(tftypes.String, "0.0.0.0/0"),
		"cidr_ipv6": tftypes.NewValue(tftypes.String, nil), "prefix_list_id": tftypes.NewValue(tftypes.String, nil),
		"referenced_security_group_id": tftypes.NewValue(tftypes.String, nil), "description": tftypes.NewValue(tftypes.String, "https"),
		"tags": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})
	args := pointArgs()
	args["vpc_id"] = tftypes.NewValue(tftypes.String, "vpc-1")
	args["group_name"] = tftypes.NewValue(tftypes.String, "web")
	args["ingress"] = tftypes.NewValue(tftypes.Map{ElementType: ruleType}, map[string]tftypes.Value{"https_public": rule})
	var m SecurityGroupRulesDataSourceModel
	if ok, errs := readDataSource(t, &SecurityGroupRulesDataSource{api: api}, args, &m); !ok {
		t.Fatalf("a group's own pipeline must plan while nothing is published: %s", errs)
	}
	kept, ok := m.IngressRules["https_public"]
	if m.Published.ValueBool() || !m.Version.IsNull() || !ok || kept.CIDRIPv4.ValueString() != "0.0.0.0/0" || len(m.Revoked)+len(m.Pending) != 0 {
		t.Errorf("published %v version %v kept %+v revoked %v pending %v, want every declared rule back unchanged", m.Published, m.Version, m.IngressRules, m.Revoked, m.Pending)
	}
}

func TestStatusOfAnAccountWithNothingPublishedIsQuiet(t *testing.T) {
	t.Parallel()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusNotFound, xshieldNotPublished}})
	var m EnforcementStatusDataSourceModel
	if ok, errs := readDataSource(t, &EnforcementStatusDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatalf("a monitor must not fail on an account with nothing published: %s", errs)
	}
	if m.Published.ValueBool() || m.State.ValueString() != "unpublished" || !m.ExpectedVersion.IsNull() || !m.AppliedVersion.IsNull() ||
		len(m.Notices)+len(m.DriftFindings)+len(m.PendingRulesAdded) != 0 || m.DriftEvaluated.ValueBool() {
		t.Errorf("status %+v, want unpublished with nothing to report", m)
	}
	if len(*requested) != 1 {
		t.Errorf("requested %v; drift of nothing published has nothing to read", *requested)
	}
}

func TestDriftIsUnevaluatedOnlyWhenXshieldSaysWhy(t *testing.T) {
	t.Parallel()
	status := cannedResponse{http.StatusOK, readTestdata(t, "status.json")}
	for name, tc := range map[string]struct {
		drift  cannedResponse
		planOK bool
	}{
		"nothing applied yet":       {cannedResponse{http.StatusConflict, xshieldNotApplied}, true},
		"nothing observed yet":      {cannedResponse{http.StatusNotFound, xshieldNotObserved}, true},
		"404 without a code":        {cannedResponse{http.StatusNotFound, `{"message":"no Route matched with those values"}`}, false},
		"409 without a code":        {cannedResponse{http.StatusConflict, `{"message":"conflict"}`}, false},
		"not published, mid-read":   {cannedResponse{http.StatusNotFound, xshieldNotPublished}, false},
		"notObserved, but as a 409": {cannedResponse{http.StatusConflict, xshieldNotObserved}, false},
	} {
		api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": status, "/drift": tc.drift})
		var m EnforcementStatusDataSourceModel
		ok, errs := readDataSource(t, &EnforcementStatusDataSource{api: api}, pointArgs(), &m)
		if ok != tc.planOK {
			t.Errorf("%s: plan ok %v, want %v (%s)", name, ok, tc.planOK, errs)
		}
		if ok && (m.DriftEvaluated.ValueBool() || len(m.DriftFindings) != 0 || !m.Published.ValueBool()) {
			t.Errorf("%s: %+v, want published with drift unevaluated", name, m)
		}
	}
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

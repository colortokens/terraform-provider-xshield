package provider

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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const xshieldNotPublished = `{"status":404,"code":"notPublished","message":"no snapshot published for this account and region"}`

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
	var m enforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &enforcementSnapshotDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatalf("an account with nothing published must plan, not fail: %s", errs)
	}
	if m.Published.ValueBool() || !m.Version.IsNull() {
		t.Errorf("published %v version %v, want false and null", m.Published, m.Version)
	}
	if len(m.SecurityGroups)+len(m.IngressRules)+len(m.EgressRules)+len(m.InterfaceAttachments)+len(m.Directory)+len(m.Assets)+len(m.Withdrawing) != 0 {
		t.Errorf("an unpublished snapshot must hold nothing to create: %+v", m)
	}
	if len(*requested) != 1 {
		t.Errorf("requested %v, want only the expected version", *requested)
	}
}

// A snapshot is applied by an AWS provider set up for one account and region; one served for any other must not be.
func TestSnapshotForAnotherAccountIsRefused(t *testing.T) {
	t.Parallel()
	other := strings.Replace(readTestdata(t, "snapshot.json"), `"cloudAccountId": "123456789012"`, `"cloudAccountId": "210987654321"`, 1)
	if !strings.Contains(other, "210987654321") {
		t.Fatal("the fixture no longer names its account as expected")
	}
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/expected":                {http.StatusOK, `{"version":"` + testVersion + `"}`},
		"/versions/" + testVersion: {http.StatusOK, other},
	})
	var m enforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &enforcementSnapshotDataSource{api: api}, pointArgs(), &m); ok || !strings.Contains(errs, "another account or region") {
		t.Errorf("ok=%v %q, want the snapshot for 210987654321 refused", ok, errs)
	}
}

func TestPublishedSnapshotSaysSo(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/expected":                {http.StatusOK, `{"version":"` + testVersion + `"}`},
		"/versions/" + testVersion: {http.StatusOK, readTestdata(t, "snapshot.json")},
	})
	var m enforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &enforcementSnapshotDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatal(errs)
	}
	served := loadJSON[wireSnapshot](t, "snapshot.json")
	if !m.Published.ValueBool() || m.Version.ValueString() != served.Version || len(m.SecurityGroups) == 0 {
		t.Errorf("published %v version %v groups %d, want true, the served version and the snapshot's groups", m.Published, m.Version, len(m.SecurityGroups))
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
		"expected version gone":    {"/expected": {http.StatusOK, `{"version":"` + testVersion + `"}`}},
	} {
		api, _ := newRoutedSnapshotAPI(t, routes)
		var m enforcementSnapshotDataSourceModel
		if ok, _ := readDataSource(t, &enforcementSnapshotDataSource{api: api}, pointArgs(), &m); ok {
			t.Errorf("%s: the plan went ahead with %+v", name, m)
		}
	}
}

// A pinned enforcement workspace still runs, so its reads must keep last_checked_at current.
func TestPinnedEnforcementReadStillRecordsTheCheck(t *testing.T) {
	t.Parallel()
	served := loadJSON[wireSnapshot](t, "snapshot.json")
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/expected":                   {http.StatusOK, `{"version":"` + strings.Repeat("ab", 64) + `"}`},
		"/versions/" + served.Version: {http.StatusOK, readTestdata(t, "snapshot.json")},
	})
	args := pointArgs()
	args["version"] = tftypes.NewValue(tftypes.String, served.Version)
	var m enforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &enforcementSnapshotDataSource{api: api}, args, &m); !ok {
		t.Fatal(errs)
	}
	if m.Version.ValueString() != served.Version {
		t.Errorf("version %v, want the pinned one", m.Version)
	}
	if !slices.ContainsFunc(*requested, func(p string) bool { return strings.HasSuffix(p, "/expected") }) {
		t.Errorf("requested %v, want the expected version read, which records the pipeline's check", *requested)
	}
}

func TestPinnedVersionMustExistEvenWhenNothingIsPublished(t *testing.T) {
	t.Parallel()
	pinned := strings.Repeat("cd", 64)
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/expected":           {http.StatusNotFound, xshieldNotPublished},
		"/versions/" + pinned: {http.StatusNotFound, `{"status":404,"message":"unknown snapshot version"}`},
	})
	args := pointArgs()
	args["version"] = tftypes.NewValue(tftypes.String, pinned)
	var m enforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &enforcementSnapshotDataSource{api: api}, args, &m); ok || !strings.Contains(errs, "version "+pinned) {
		t.Errorf("a pin to a version Xshield does not hold must fail, naming it; got ok=%v %q", ok, errs)
	}
}

func TestDeclaredRulesComeBackUnchangedWhenNothingIsPublished(t *testing.T) {
	t.Parallel()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusNotFound, xshieldNotPublished}})
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
	var m securityGroupRulesDataSourceModel
	if ok, errs := readDataSource(t, &securityGroupRulesDataSource{api: api}, args, &m); !ok {
		t.Fatalf("a group's own pipeline must plan while nothing is published: %s", errs)
	}
	kept, ok := m.IngressRules["https_public"]
	if m.Published.ValueBool() || !m.Version.IsNull() || !ok || kept.CIDRIPv4.ValueString() != "0.0.0.0/0" || len(m.Revoked)+len(m.Pending) != 0 {
		t.Errorf("published %v version %v kept %+v revoked %v pending %v, want every declared rule back unchanged", m.Published, m.Version, m.IngressRules, m.Revoked, m.Pending)
	}
	if slices.ContainsFunc(*requested, func(p string) bool { return strings.HasSuffix(p, "/expected") }) {
		t.Errorf("requested %v: a team's rules filter read the expected version, which Xshield records as the enforcement pipeline's last check", *requested)
	}
}

func TestStatusOfAnAccountWithNothingPublishedIsQuiet(t *testing.T) {
	t.Parallel()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusNotFound, xshieldNotPublished}})
	var m enforcementStatusDataSourceModel
	if ok, errs := readDataSource(t, &enforcementStatusDataSource{api: api}, pointArgs(), &m); !ok {
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

// Drift arrives with the status once Xshield has a receipt and an observation; until then it reads as unevaluated.
func TestStatusWithoutDriftReadsAsUnevaluated(t *testing.T) {
	t.Parallel()
	st := loadJSON[map[string]any](t, "status.json")
	delete(st, "drift")
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusOK, string(body)}})
	var m enforcementStatusDataSourceModel
	if ok, errs := readDataSource(t, &enforcementStatusDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatalf("a status without drift must plan: %s", errs)
	}
	if m.DriftEvaluated.ValueBool() || len(m.DriftFindings) != 0 || !m.DriftObservedAt.IsNull() || !m.Published.ValueBool() {
		t.Errorf("%+v, want published with drift unevaluated", m)
	}
	if len(*requested) != 1 {
		t.Errorf("requested %v, want the status alone", *requested)
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

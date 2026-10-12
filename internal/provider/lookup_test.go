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
	"strings"
	"sync"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	providerTestKeyOnce sync.Once
	providerTestKeyPEM  string
)

// newLookupClient returns an SDK bound to a server that records the criteria it
// was sent and replies with the given JSON.
func newLookupClient(t *testing.T, responseBody string) (*sdk.Xshield, *string) {
	t.Helper()
	providerTestKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		providerTestKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
	})

	var sentCriteria string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Criteria string `json:"criteria"`
		}
		_ = json.Unmarshal(raw, &body)
		sentCriteria = body.Criteria
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, responseBody)
	}))
	t.Cleanup(srv.Close)

	client := sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", providerTestKeyPEM)),
		sdk.WithClient(srv.Client()),
	)
	return client, &sentCriteria
}

func TestCriteriaNameEquals(t *testing.T) {
	t.Parallel()
	// The criteria grammar has no escape sequence inside a quoted literal, so a
	// name carrying a quote has to switch quote characters. Interpolating
	// blindly produced a syntax error with no hint about the cause.
	for _, tc := range []struct {
		name    string
		want    string
		wantErr bool
	}{
		{name: "payroll-db", want: "templateName = 'payroll-db'"},
		{name: "Bob's servers", want: `templateName = "Bob's servers"`},
		{name: `say "hi"`, want: `templateName = 'say "hi"'`},
		{name: `both ' and "`, wantErr: true},
	} {
		got, err := criteriaNameEquals("templateName", tc.name)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("criteriaNameEquals(%q) should have failed, got %q", tc.name, got)
		case !tc.wantErr && err != nil:
			t.Errorf("criteriaNameEquals(%q): %v", tc.name, err)
		case !tc.wantErr && got != tc.want:
			t.Errorf("criteriaNameEquals(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestUniqueMatch(t *testing.T) {
	t.Parallel()
	if got, err := uniqueMatch("template", "web", []string{"t1"}); err != nil || got != "t1" {
		t.Errorf("single match: got %q, %v", got, err)
	}
	if _, err := uniqueMatch("template", "web", nil); err == nil {
		t.Error("no match should be an error, not an empty id")
	} else if !strings.Contains(err.Error(), "no template named") {
		t.Errorf("unhelpful message: %v", err)
	}
	// Returning the first hit silently bound the configuration to an arbitrary
	// object; asset names in particular are not unique.
	_, err := uniqueMatch("asset", "web-01", []string{"a1", "a2"})
	if err == nil {
		t.Fatal("an ambiguous name should be an error")
	}
	if !strings.Contains(err.Error(), "use the id instead") {
		t.Errorf("message should say what to do instead: %v", err)
	}
}

func TestFindTemplateIDByNameFiltersToExactMatch(t *testing.T) {
	t.Parallel()
	// The search endpoint matches loosely, so the caller has to filter.
	client, sent := newLookupClient(t, `{"items":[
		{"templateId":"t-loose","templateName":"payroll-db-archive"},
		{"templateId":"t-exact","templateName":"payroll-db"}
	]}`)

	got, err := findTemplateIDByName(context.Background(), client, "payroll-db")
	if err != nil {
		t.Fatalf("findTemplateIDByName: %v", err)
	}
	if got != "t-exact" {
		t.Errorf("resolved to %q, want the exactly matching template", got)
	}
	if *sent != "templateName = 'payroll-db'" {
		t.Errorf("criteria sent = %q", *sent)
	}
}

func TestFindTemplateIDByNameRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	client, _ := newLookupClient(t, `{"items":[
		{"templateId":"t1","templateName":"payroll-db"},
		{"templateId":"t2","templateName":"payroll-db"}
	]}`)

	if _, err := findTemplateIDByName(context.Background(), client, "payroll-db"); err == nil {
		t.Fatal("two templates with the same name should be an error")
	}
}

func TestFindTemplateIDByNameReportsNotFound(t *testing.T) {
	t.Parallel()
	client, _ := newLookupClient(t, `{"items":[]}`)

	_, err := findTemplateIDByName(context.Background(), client, "absent")
	if err == nil {
		t.Fatal("a missing template should be an error")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("the message should name the template: %v", err)
	}
}

func TestFindAssetIDByNameQuotesAwkwardNames(t *testing.T) {
	t.Parallel()
	client, sent := newLookupClient(t, `{"items":[{"assetId":"a-1","assetName":"Bob's laptop","type":"endpoint"}]}`)

	got, err := findAssetIDByName(context.Background(), client, "Bob's laptop")
	if err != nil {
		t.Fatalf("findAssetIDByName: %v", err)
	}
	if got != "a-1" {
		t.Errorf("resolved to %q", got)
	}
	if *sent != `assetName = "Bob's laptop"` {
		t.Errorf("criteria sent = %q, want the double-quoted form", *sent)
	}
}

func TestFindSegmentAndNamedNetworkAndTagRuleByName(t *testing.T) {
	t.Parallel()
	t.Run("segment", func(t *testing.T) {
		t.Parallel()
		client, sent := newLookupClient(t, `{"items":[{"tagBasedPolicyId":"s-1","tagBasedPolicyName":"payroll"}]}`)
		got, err := findSegmentIDByName(context.Background(), client, "payroll")
		if err != nil || got != "s-1" {
			t.Fatalf("got %q, %v", got, err)
		}
		if *sent != "tagBasedPolicyName = 'payroll'" {
			t.Errorf("criteria = %q", *sent)
		}
	})
	t.Run("named network", func(t *testing.T) {
		t.Parallel()
		client, sent := newLookupClient(t, `{"items":[{"namedNetworkId":"nn-1","namedNetworkName":"corp"}]}`)
		got, err := findNamedNetworkIDByName(context.Background(), client, "corp")
		if err != nil || got != "nn-1" {
			t.Fatalf("got %q, %v", got, err)
		}
		if *sent != "namedNetworkName = 'corp'" {
			t.Errorf("criteria = %q", *sent)
		}
	})
	t.Run("tag rule", func(t *testing.T) {
		t.Parallel()
		client, sent := newLookupClient(t, `{"items":[{"ruleId":"r-1","ruleName":"tag-prod","ruleCriteria":"*"}]}`)
		got, err := findTagRuleIDByName(context.Background(), client, "tag-prod")
		if err != nil || got != "r-1" {
			t.Fatalf("got %q, %v", got, err)
		}
		if *sent != "ruleName = 'tag-prod'" {
			t.Errorf("criteria = %q", *sent)
		}
	})
}

func TestIsXshieldUUID(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"a1b2c3d4-0000-0000-0000-000000000000": true,
		"A1B2C3D4-0000-0000-0000-000000000000": true,
		"payroll-db":                           false,
		"":                                     false,
		"a1b2c3d4-0000-0000-0000-00000000000":  false,
	} {
		if got := isXshieldUUID(in); got != want {
			t.Errorf("isXshieldUUID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestResolveSegmentReferencesFillsInIDsFromNames(t *testing.T) {
	t.Parallel()
	// The schema accepts a template or named network by name, but the create
	// payload and the update diff both key on the id, so a name-only entry used
	// to be dropped on create and collide under the empty key on update.
	client, _ := newLookupClient(t, `{"items":[{"templateId":"t-1","templateName":"payroll-web"}]}`)

	data := &SegmentResourceModel{
		Templates: []tfTypes.TemplateReference{
			{TemplateName: types.StringValue("payroll-web")},
		},
	}
	var diags diag.Diagnostics
	resolveSegmentReferences(context.Background(), client, data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}
	if got := data.Templates[0].TemplateID.ValueString(); got != "t-1" {
		t.Errorf("template_id = %q, want the resolved id %q", got, "t-1")
	}
}

func TestResolveSegmentReferencesLeavesExplicitIDsAlone(t *testing.T) {
	t.Parallel()
	// An entry that already carries an id must not trigger a lookup, so the
	// server here would fail the test if it were called.
	client, sent := newLookupClient(t, `{"items":[{"templateId":"wrong","templateName":"payroll-web"}]}`)

	data := &SegmentResourceModel{
		Templates: []tfTypes.TemplateReference{
			{TemplateID: types.StringValue("t-explicit"), TemplateName: types.StringValue("payroll-web")},
		},
	}
	var diags diag.Diagnostics
	resolveSegmentReferences(context.Background(), client, data, &diags)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}
	if got := data.Templates[0].TemplateID.ValueString(); got != "t-explicit" {
		t.Errorf("template_id = %q, want it left as written", got)
	}
	if *sent != "" {
		t.Errorf("a lookup was issued for an entry that already had an id: %q", *sent)
	}
}

func TestResolveSegmentReferencesReportsAnUnknownName(t *testing.T) {
	t.Parallel()
	client, _ := newLookupClient(t, `{"items":[]}`)

	data := &SegmentResourceModel{
		Namednetworks: []tfTypes.MetadataNamedNetworkReference{
			{NamedNetworkName: types.StringValue("absent")},
		},
	}
	var diags diag.Diagnostics
	resolveSegmentReferences(context.Background(), client, data, &diags)

	if !diags.HasError() {
		t.Fatal("an unresolvable named network should raise a diagnostic, not apply silently")
	}
	if !strings.Contains(diags.Errors()[0].Detail(), "absent") {
		t.Errorf("the diagnostic should name the network: %v", diags.Errors()[0])
	}
}

func TestResolveAssetLookupAcceptsANameInsteadOfAUUID(t *testing.T) {
	t.Parallel()
	client, criteria := newLookupClient(t, `{"items":[{"assetId":"a1b2c3d4-0000-0000-0000-000000000000","assetName":"web-01"}]}`)

	var diags diag.Diagnostics
	data := &AssetDataSourceModel{AssetName: types.StringValue("web-01")}
	id, ok := resolveAssetLookup(context.Background(), client, data, &diags)

	if !ok || diags.HasError() {
		t.Fatalf("resolving by name failed: %v", diags)
	}
	if id != "a1b2c3d4-0000-0000-0000-000000000000" {
		t.Errorf("id = %q", id)
	}
	if !strings.Contains(*criteria, "web-01") {
		t.Errorf("the name never reached the search criteria: %q", *criteria)
	}
}

func TestResolveAssetLookupRejectsAmbiguousAndEmptyConfigs(t *testing.T) {
	t.Parallel()
	client, _ := newLookupClient(t, `{"items":[]}`)

	for _, tc := range []struct {
		name string
		data *AssetDataSourceModel
	}{
		{"both set", &AssetDataSourceModel{
			ID:        types.StringValue("a1b2c3d4-0000-0000-0000-000000000000"),
			AssetName: types.StringValue("web-01"),
		}},
		{"neither set", &AssetDataSourceModel{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			if _, ok := resolveAssetLookup(context.Background(), client, tc.data, &diags); ok {
				t.Error("expected the lookup to be refused")
			}
			if !diags.HasError() {
				t.Error("expected an error explaining how to identify the asset")
			}
		})
	}
}

func TestResolveAssetLookupPassesAUUIDStraightThrough(t *testing.T) {
	t.Parallel()
	// No search should happen when the id is already known.
	client, criteria := newLookupClient(t, `{"items":[]}`)

	var diags diag.Diagnostics
	data := &AssetDataSourceModel{ID: types.StringValue("a1b2c3d4-0000-0000-0000-000000000000")}
	id, ok := resolveAssetLookup(context.Background(), client, data, &diags)

	if !ok || diags.HasError() {
		t.Fatalf("resolving by id failed: %v", diags)
	}
	if id != "a1b2c3d4-0000-0000-0000-000000000000" {
		t.Errorf("id = %q", id)
	}
	if *criteria != "" {
		t.Errorf("an id lookup should not search, but sent criteria %q", *criteria)
	}
}

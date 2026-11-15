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
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

type changesRequest struct {
	requestURI string
	header     http.Header
	workspace  []string
}

// changesServer answers every customergroupchanges read with one published change and records each request.
func changesServer(t *testing.T) (string, func() []changesRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []changesRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, changesRequest{requestURI: r.RequestURI, header: r.Header.Clone(), workspace: r.URL.Query()["workspace"]})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"cloudAccountId":"123456789012","region":"us-east-1","version":"v-2","customerGroupChanges":{"vpc-1/web":{"groupId":"sg-0web"}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []changesRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]changesRequest(nil), seen...)
	}
}

// configureProvider runs the provider's Configure on a block that sets block, as Terraform would, and returns
// what it hands its data sources.
func configureProvider(t *testing.T, block map[string]tftypes.Value) (any, diag.Diagnostics) {
	t.Helper()
	ctx := context.Background()
	p := New("test")()
	var schemaResp fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &schemaResp)
	objectType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, attrType := range objectType.AttributeTypes {
		values[name] = tftypes.NewValue(attrType, nil)
	}
	for name, value := range block {
		if _, ok := objectType.AttributeTypes[name]; !ok {
			t.Fatalf("the provider block has no %s attribute", name)
		}
		values[name] = value
	}
	var resp fwprovider.ConfigureResponse
	p.Configure(ctx, fwprovider.ConfigureRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objectType, values)}}, &resp)
	return resp.DataSourceData, resp.Diagnostics
}

func signedBlock(t *testing.T, serverURL string) (map[string]tftypes.Value, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return map[string]tftypes.Value{
		"server_url":  tftypes.NewValue(tftypes.String, serverURL),
		"tenancy_id":  tftypes.NewValue(tftypes.String, "tenancy"),
		"user_id":     tftypes.NewValue(tftypes.String, "user"),
		"fingerprint": tftypes.NewValue(tftypes.String, "fp"),
		"private_key": tftypes.NewValue(tftypes.String, keyPEM),
	}, &key.PublicKey
}

// readChangesThroughTheProvider reads the listing and one group's rules as an owner workspace's plan does.
func readChangesThroughTheProvider(t *testing.T, providerData any) {
	t.Helper()
	ctx := context.Background()
	rulesArgs := pointArgs()
	rulesArgs["vpc_id"] = tftypes.NewValue(tftypes.String, "vpc-1")
	rulesArgs["group_name"] = tftypes.NewValue(tftypes.String, "web")
	for _, read := range []struct {
		ds   datasource.DataSource
		args map[string]tftypes.Value
		out  any
	}{
		{newAWSSecurityGroupChangesDataSource(), pointArgs(), &awsSecurityGroupChangesDataSourceModel{}},
		{newAWSSecurityGroupRulesDataSource(), rulesArgs, &awsSecurityGroupRulesDataSourceModel{}},
	} {
		var configured datasource.ConfigureResponse
		read.ds.(datasource.DataSourceWithConfigure).Configure(ctx, datasource.ConfigureRequest{ProviderData: providerData}, &configured)
		if configured.Diagnostics.HasError() {
			t.Fatal(configured.Diagnostics)
		}
		if ok, errs := readDataSource(t, read.ds, read.args, read.out); !ok {
			t.Fatalf("read failed: %s", errs)
		}
	}
}

// A revert keeps the access Xshield moved into cohort groups until the workspace that owns the group has read the
// changes again, so each read says which workspace made it: HCP Terraform's own workspace ID first, then the
// provider block's workspace_id.
func TestCustomerGroupChangesReadNamesTheWorkspace(t *testing.T) {
	for name, test := range map[string]struct {
		tfcWorkspaceID string
		workspaceID    *string
		want           []string
	}{
		"in HCP Terraform":                   {tfcWorkspaceID: "ws-AbC123", want: []string{"ws-AbC123"}},
		"from the provider block":            {workspaceID: ptr("owner/web & db"), want: []string{"owner/web & db"}},
		"HCP Terraform's ID over the block":  {tfcWorkspaceID: "ws-AbC123", workspaceID: ptr("owner-web"), want: []string{"ws-AbC123"}},
		"neither":                            {},
		"an empty workspace_id in the block": {workspaceID: ptr("")},
	} {
		t.Run(name, func(t *testing.T) {
			clearXshieldEnv(t)
			t.Setenv("TFC_WORKSPACE_ID", test.tfcWorkspaceID)
			serverURL, requests := changesServer(t)
			block, pub := signedBlock(t, serverURL)
			if test.workspaceID != nil {
				block["workspace_id"] = tftypes.NewValue(tftypes.String, *test.workspaceID)
			}
			providerData, diags := configureProvider(t, block)
			if diags.HasError() {
				t.Fatal(diags)
			}

			readChangesThroughTheProvider(t, providerData)

			seen := requests()
			if len(seen) != 1 {
				t.Fatalf("requested %d times, want one read shared by both data sources", len(seen))
			}
			got := seen[0]
			if !strings.HasPrefix(got.requestURI, "/api/policies/cloudsnapshots/aws/123456789012/us-east-1/customergroupchanges") {
				t.Errorf("requested %s", got.requestURI)
			}
			if strings.Join(got.workspace, ",") != strings.Join(test.want, ",") {
				t.Errorf("sent workspace %q in %s, want %q", got.workspace, got.requestURI, test.want)
			}
			if test.want == nil && strings.Contains(got.requestURI, "?") {
				t.Errorf("requested %s, want no query when no workspace is known", got.requestURI)
			}
			verifySignedAsTheGatewayChecks(t, got, pub)
		})
	}
}

// The gateway checks the signature over the request target with its query, so the workspace must be part of what is signed.
func verifySignedAsTheGatewayChecks(t *testing.T, got changesRequest, pub *rsa.PublicKey) {
	t.Helper()
	match := regexp.MustCompile(`signature="([^"]+)"`).FindStringSubmatch(got.header.Get("Authorization"))
	if match == nil {
		t.Fatalf("unsigned request: %v", got.header)
	}
	signature, err := base64.RawStdEncoding.DecodeString(match[1])
	if err != nil {
		t.Fatal(err)
	}
	material := strings.Join([]string{
		"(request-target): get " + got.requestURI,
		"date: " + got.header.Get("date"),
		"host: 127.0.0.1",
		"x-content-sha256: " + got.header.Get("x-content-sha256"),
	}, "\n")
	digest := sha256.Sum256([]byte(material))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, nil); err != nil {
		t.Errorf("the gateway would refuse %s: %v", got.requestURI, err)
	}
}

// A workspace_id the plan learns only at apply would leave the plan's own read unnamed, and the revert would not
// wait for it.
func TestAWorkspaceIDUnknownAtPlanIsRefused(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("TFC_WORKSPACE_ID", "")
	block, _ := signedBlock(t, "http://127.0.0.1:1")
	block["workspace_id"] = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	_, diags := configureProvider(t, block)
	if !diags.HasError() {
		t.Fatal("configured a provider whose workspace_id is not known")
	}
	for _, d := range diags.Errors() {
		withPath, ok := d.(diag.DiagnosticWithPath)
		if !ok || withPath.Path().String() != "workspace_id" {
			t.Errorf("error %q is not on workspace_id", d.Summary())
		}
	}
}

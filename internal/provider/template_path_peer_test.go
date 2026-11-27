package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const peerTestTemplateID = "tmpl-db"

type templateAPIRecord struct {
	mu       sync.Mutex
	appended []shared.MetadataPath
}

func newTemplateAPI(t *testing.T, template string) (*sdk.Xshield, *templateAPIRecord) {
	t.Helper()
	newLookupClient(t, "{}")
	record := &templateAPIRecord{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		base := "/api/v2/templates/" + peerTestTemplateID
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			_, _ = io.WriteString(w, template)
		case r.Method == http.MethodPut && r.URL.Path == base+"/append":
			var body shared.TemplateBodyWithComment
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("append body: %v", err)
			}
			record.mu.Lock()
			record.appended = append(record.appended, body.TemplatePaths...)
			record.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodDelete && r.URL.Path == base+"/deduct":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", providerTestKeyPEM)),
		sdk.WithClient(srv.Client()),
	), record
}

func templateWithPaths(paths ...tfTypes.MetadataPath) TemplateResourceModel {
	return TemplateResourceModel{
		ID:            types.StringValue(peerTestTemplateID),
		TemplateName:  types.StringValue("db"),
		TemplateType:  types.StringValue("application-template"),
		TemplatePaths: paths,
	}
}

func inboundMySQLPath(id string) tfTypes.MetadataPath {
	return tfTypes.MetadataPath{
		ID:        types.StringValue(id),
		Direction: types.StringValue("inbound"),
		Port:      types.StringValue("3306"),
		Protocol:  types.StringValue("TCP"),
	}
}

// templateValue is the model as Terraform holds it, for a plan, the state or the configuration.
func templateValue(t *testing.T, s schema.Schema, model TemplateResourceModel) tftypes.Value {
	t.Helper()
	holder := tfsdk.Plan{Schema: s}
	if d := holder.Set(context.Background(), model); d.HasError() {
		t.Fatal(d)
	}
	return holder.Raw
}

func TestTemplatePathChangedFromAnAssetPeerToAnIPPeerIsReAddedWithOnlyTheIPPeer(t *testing.T) {
	ctx := context.Background()
	client, record := newTemplateAPI(t, `{"templateName":"db","templateType":"application-template","templatePaths":[
		{"channelHash":"h-new","direction":"inbound","port":"3306","protocol":"TCP","srcIp":"192.168.0.0/16"}]}`)
	r := &TemplateResource{client: client}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	s := schemaResp.Schema

	held := inboundMySQLPath("h-old")
	held.SourceAssetID = types.StringValue("client-asset")
	configured := inboundMySQLPath("")
	configured.ID = types.StringNull()
	configured.SrcIP = types.StringValue("192.168.0.0/16")
	planned := held
	planned.SrcIP = types.StringValue("192.168.0.0/16")

	state := tfsdk.State{Schema: s, Raw: templateValue(t, s, templateWithPaths(held))}
	plan := tfsdk.Plan{Schema: s, Raw: templateValue(t, s, templateWithPaths(planned))}
	config := tfsdk.Config{Schema: s, Raw: templateValue(t, s, templateWithPaths(configured))}

	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state, Config: config}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("update: %v", resp.Diagnostics)
	}
	if len(record.appended) != 1 {
		t.Fatalf("appended %d paths, want the one changed path", len(record.appended))
	}
	sent := record.appended[0]
	if sent.SrcIP == nil || *sent.SrcIP != "192.168.0.0/16" {
		t.Errorf("re-added path's srcIp = %v, want the configured IP peer", sent.SrcIP)
	}
	if sent.SourceAssetID != nil {
		t.Errorf("re-added path still names source asset %q: the configuration removed that peer, so the asset would keep its access", *sent.SourceAssetID)
	}
	var stored TemplateResourceModel
	if d := resp.State.Get(ctx, &stored); d.HasError() {
		t.Fatal(d)
	}
	if len(stored.TemplatePaths) != 1 || !stored.TemplatePaths[0].SrcIP.Equal(planned.SrcIP) || !stored.TemplatePaths[0].SourceAssetID.Equal(planned.SourceAssetID) {
		t.Errorf("stored paths %+v, want the planned path: Terraform fails an apply whose result differs from a known planned value", stored.TemplatePaths)
	}
}

func TestReadKeepsTheOrderOfAStateWhoseAssetPeersWereReadAsNull(t *testing.T) {
	ctx := context.Background()
	client, _ := newTemplateAPI(t, `{"templateName":"db","templateType":"application-template","templatePaths":[
		{"channelHash":"h-ip","direction":"inbound","port":"443","protocol":"TCP","srcIp":"10.0.0.0/8"},
		{"channelHash":"h-asset","direction":"inbound","port":"3306","protocol":"TCP","sourceAsset":{"assetId":"client-asset","assetName":"client"}}]}`)
	r := &TemplateResource{client: client}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	assetPeer := inboundMySQLPath("h-asset")
	ipPeer := tfTypes.MetadataPath{ID: types.StringValue("h-ip"), Direction: types.StringValue("inbound"), Port: types.StringValue("443"),
		Protocol: types.StringValue("TCP"), SrcIP: types.StringValue("10.0.0.0/8")}
	state := tfsdk.State{Schema: schemaResp.Schema, Raw: templateValue(t, schemaResp.Schema, templateWithPaths(assetPeer, ipPeer))}

	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("read: %v", resp.Diagnostics)
	}
	var read TemplateResourceModel
	if d := resp.State.Get(ctx, &read); d.HasError() {
		t.Fatal(d)
	}
	got := []string{}
	for _, p := range read.TemplatePaths {
		got = append(got, p.ID.ValueString())
	}
	if strings.Join(got, ",") != "h-asset,h-ip" {
		t.Errorf("paths read in order %v, want the state's h-asset,h-ip: Terraform compares the list by position, so a moved path plans a change", got)
	}
	if read.TemplatePaths[0].SourceAssetID.ValueString() != "client-asset" {
		t.Errorf("source_asset_id read back = %q, want client-asset", read.TemplatePaths[0].SourceAssetID.ValueString())
	}
}

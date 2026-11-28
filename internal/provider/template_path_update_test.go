package provider

import (
	"encoding/json"
	"reflect"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func templatePathWithEveryField(direction string) tfTypes.MetadataPath {
	return tfTypes.MetadataPath{
		ID:                 types.StringValue("held-path-id"),
		Direction:          types.StringValue(direction),
		Port:               types.StringValue("3306"),
		PortName:           types.StringValue("mysql"),
		Protocol:           types.StringValue("TCP"),
		SourceAssetID:      types.StringValue("client-asset"),
		SrcProcess:         types.StringValue("client"),
		DestinationAssetID: types.StringValue("server-asset"),
		DstProcess:         types.StringValue("mysqld"),
		Domain:             types.StringValue("db.example.internal"),
		Method:             types.StringValue("GET"),
		URI:                types.StringValue("/health"),
		SourceNamedNetwork: &tfTypes.MetadataNamedNetworkReference{NamedNetworkName: types.StringValue("corp-networks")},
		DestinationTagBasedPolicy: &tfTypes.MetadataTagBasedPolicyReference{
			TagBasedPolicyName: types.StringValue("payroll-db")},
	}
}

func TestUpdatedTemplatePathKeepsEveryPeerAndAttributeItSets(t *testing.T) {
	appended := appendedTemplatePaths([]tfTypes.MetadataPath{templatePathWithEveryField("inbound")})
	if len(appended) != 1 {
		t.Fatalf("appended %d paths, want 1", len(appended))
	}
	got := appended[0]
	want := map[string]*string{
		"source_asset_id": got.SourceAssetID, "src_process": got.SrcProcess, "destination_asset_id": got.DestinationAssetID,
		"dst_process": got.DstProcess, "domain": got.Domain, "method": got.Method, "uri": got.URI, "port_name": got.PortName,
	}
	expected := map[string]string{
		"source_asset_id": "client-asset", "src_process": "client", "destination_asset_id": "server-asset",
		"dst_process": "mysqld", "domain": "db.example.internal", "method": "GET", "uri": "/health", "port_name": "mysql",
	}
	for field, value := range want {
		if value == nil || *value != expected[field] {
			t.Errorf("%s on the re-added path = %v, want %q: an update deletes the path and re-adds it, so a field left out is lost", field, value, expected[field])
		}
	}
	if got.SourceNamedNetwork == nil || got.SourceNamedNetwork.NamedNetworkName == nil || *got.SourceNamedNetwork.NamedNetworkName != "corp-networks" {
		t.Errorf("a named network given by name only is lost on update: %+v", got.SourceNamedNetwork)
	}
	if got.DestinationTagBasedPolicy == nil || got.DestinationTagBasedPolicy.TagBasedPolicyName == nil {
		t.Errorf("a tag-based policy given by name only is lost on update: %+v", got.DestinationTagBasedPolicy)
	}
	if got.ID != nil {
		t.Errorf("the re-added path carries the deleted path's id %q; the API assigns a new one", *got.ID)
	}
}

func TestUpdatedTemplatePathIsWhatCreateSends(t *testing.T) {
	path := templatePathWithEveryField("outbound")
	created := (&TemplateResourceModel{TemplatePaths: []tfTypes.MetadataPath{path}}).ToSharedTemplate().TemplatePaths[0]
	created.ID = nil
	appended := appendedTemplatePaths([]tfTypes.MetadataPath{path})[0]
	if !reflect.DeepEqual(created, appended) {
		t.Errorf("the re-added path differs from the created one:\ncreate: %s\nupdate: %s", describePath(created), describePath(appended))
	}
}

func describePath(p shared.MetadataPath) string {
	value := reflect.ValueOf(p)
	out := ""
	for i := range value.NumField() {
		field := value.Field(i)
		if field.Kind() == reflect.Pointer && !field.IsNil() {
			out += value.Type().Field(i).Name + " "
		}
	}
	return out
}

func TestTemplatePathSelectorKnownOnlyAtApplyPassesValidation(t *testing.T) {
	for _, path := range []tfTypes.MetadataPath{
		{Direction: types.StringValue("inbound"), Port: types.StringValue("3306"), Protocol: types.StringValue("TCP"), SourceAssetID: types.StringUnknown()},
		{Direction: types.StringValue("inbound"), Port: types.StringValue("3306"), Protocol: types.StringValue("TCP"), SrcIP: types.StringUnknown()},
		{Direction: types.StringValue("outbound"), Port: types.StringValue("443"), Protocol: types.StringValue("TCP"), DestinationAssetID: types.StringUnknown()},
		{Direction: types.StringValue("outbound"), Port: types.StringValue("443"), Protocol: types.StringValue("TCP"), DstIP: types.StringUnknown()},
		{Direction: types.StringValue("outbound"), Port: types.StringValue("443"), Protocol: types.StringValue("TCP"), Domain: types.StringUnknown()},
	} {
		var diags diag.Diagnostics
		validateTemplatePaths(&TemplateResourceModel{TemplatePaths: []tfTypes.MetadataPath{path}}, &diags)
		if diags.HasError() {
			t.Errorf("a %s path whose selector is known only at apply, as one from a variable or another resource is, fails validation: %v",
				path.Direction.ValueString(), diags)
		}
	}
}

func TestTemplatePathWithNoSelectorStillFailsValidation(t *testing.T) {
	var diags diag.Diagnostics
	validateTemplatePaths(&TemplateResourceModel{TemplatePaths: []tfTypes.MetadataPath{
		{Direction: types.StringValue("inbound"), Port: types.StringValue("3306"), Protocol: types.StringValue("TCP"), SourceAssetID: types.StringNull()},
	}}, &diags)
	if !diags.HasError() {
		t.Error("an inbound path naming no source passes validation")
	}
}

func TestTemplateReadKeepsThePathsAssetPeers(t *testing.T) {
	var read shared.Template
	if err := json.Unmarshal([]byte(`{"templateName":"db","templateType":"application-template","templatePaths":[
		{"channelHash":"p1","direction":"inbound","port":"3306","protocol":"TCP","sourceAsset":{"assetId":"client-asset","assetName":"client"}},
		{"channelHash":"p2","direction":"outbound","port":"443","protocol":"TCP","destinationAsset":{"assetId":"server-asset","assetName":"server"}}]}`), &read); err != nil {
		t.Fatal(err)
	}
	var model TemplateResourceModel
	model.RefreshFromSharedTemplate(&read)
	if len(model.TemplatePaths) != 2 {
		t.Fatalf("read %d paths, want 2", len(model.TemplatePaths))
	}
	if got := model.TemplatePaths[0].SourceAssetID.ValueString(); got != "client-asset" {
		t.Errorf("source_asset_id read back = %q, want client-asset: the API names a path's asset peer as an asset, not by its id", got)
	}
	if got := model.TemplatePaths[1].DestinationAssetID.ValueString(); got != "server-asset" {
		t.Errorf("destination_asset_id read back = %q, want server-asset", got)
	}
}

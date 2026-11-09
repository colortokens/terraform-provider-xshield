package provider

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func cloudIsRefused(ctx context.Context, validators []validator.String, cloud string) bool {
	var resp validator.StringResponse
	for _, v := range validators {
		v.ValidateString(ctx, validator.StringRequest{Path: path.Root("cloud"), ConfigValue: types.StringValue(cloud)}, &resp)
	}
	return resp.Diagnostics.HasError()
}

func receiptSchema(ctx context.Context) schema.Schema {
	var resp resource.SchemaResponse
	(&enforcementReceiptResource{}).Schema(ctx, resource.SchemaRequest{}, &resp)
	return resp.Schema
}

// Receipts in state already name their cloud, so supporting another one adds a value, not an attribute that every
// AWS receipt would have to be replaced to gain.
func TestReceiptCloudDefaultsToAWSAcceptsNothingElseAndReplacesWhenChanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := receiptSchema(ctx)
	cloud, ok := s.Attributes["cloud"].(schema.StringAttribute)
	if !ok || !cloud.Optional || !cloud.Computed || cloud.Default == nil {
		t.Fatalf("cloud is %#v, want optional with a default", s.Attributes["cloud"])
	}
	var byDefault defaults.StringResponse
	cloud.Default.DefaultString(ctx, defaults.StringRequest{}, &byDefault)
	if byDefault.PlanValue.ValueString() != cloudAWS {
		t.Errorf("cloud defaults to %s, want %s", byDefault.PlanValue, cloudAWS)
	}
	if cloudIsRefused(ctx, cloud.Validators, "aws") || !cloudIsRefused(ctx, cloud.Validators, "azure") {
		t.Error("cloud must accept aws and only aws")
	}

	objectType := s.Type().TerraformType(ctx).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, attrType := range objectType.AttributeTypes {
		values[name] = tftypes.NewValue(attrType, nil)
	}
	existing := tftypes.NewValue(objectType, values)
	req := planmodifier.StringRequest{
		Path:        path.Root("cloud"),
		State:       tfsdk.State{Schema: s, Raw: existing},
		Plan:        tfsdk.Plan{Schema: s, Raw: existing},
		StateValue:  types.StringValue(cloudAWS),
		PlanValue:   types.StringValue("azure"),
		ConfigValue: types.StringValue("azure"),
	}
	var changed planmodifier.StringResponse
	for _, m := range cloud.PlanModifiers {
		m.PlanModifyString(ctx, req, &changed)
	}
	if !changed.RequiresReplace {
		t.Error("a receipt sent for one cloud must be replaced, not updated, to name another")
	}
}

// State written before the attribute existed reads as AWS, the only cloud a receipt was sent for, so no receipt is
// replaced or sent again to gain it.
func TestReceiptStateWithoutACloudReadsAsAWS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	held := loadJSON[wireConvergence](t, "status.json")
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusOK, readTestdata(t, "status.json")}})
	s := receiptSchema(ctx)
	stored := tfsdk.State{Schema: s}
	model := enforcementReceiptResourceModel{
		ID: types.StringValue(held.Applied.ReceiptID), Cloud: types.StringNull(), CloudAccountID: types.StringValue("123456789012"),
		Region: types.StringValue("us-east-1"), Workspace: types.StringValue("ws"), SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups: types.MapNull(types.StringType), Rules: types.MapNull(types.StringType), Attachments: types.MapNull(types.StringType),
		RunID: types.StringValue(""), AppliedAt: types.StringValue("2026-01-01T00:00:00Z"),
	}
	if diags := stored.Set(ctx, model); diags.HasError() {
		t.Fatal(diags)
	}
	resp := resource.ReadResponse{State: stored}

	(&enforcementReceiptResource{api: api}).Read(ctx, resource.ReadRequest{State: stored}, &resp)

	if resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("the receipt left state: %v", resp.Diagnostics)
	}
	var cloud types.String
	resp.State.GetAttribute(ctx, path.Root("cloud"), &cloud)
	if cloud.ValueString() != cloudAWS {
		t.Errorf("cloud reads as %s, want %s", cloud, cloudAWS)
	}
	if !slices.Equal(*requested, []string{"/api/policies/cloudsnapshots/aws/123456789012/us-east-1/status"}) {
		t.Errorf("requested %v", *requested)
	}
}

// The import id names an AWS account and region. One with more parts is refused rather than read as an account
// whose region holds a slash, so an id that names the cloud first stays free to add.
func TestReceiptImportIDIsAnAWSAccountAndRegion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := receiptSchema(ctx)
	importID := func(id string) (resource.ImportStateResponse, bool) {
		resp := resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
		(&enforcementReceiptResource{}).ImportState(ctx, resource.ImportStateRequest{ID: id}, &resp)
		return resp, !resp.Diagnostics.HasError()
	}

	resp, ok := importID("123456789012/us-east-1")
	if !ok {
		t.Fatalf("an account and region were refused: %v", resp.Diagnostics)
	}
	var cloud, account, region types.String
	resp.State.GetAttribute(ctx, path.Root("cloud"), &cloud)
	resp.State.GetAttribute(ctx, path.Root("cloud_account_id"), &account)
	resp.State.GetAttribute(ctx, path.Root("region"), &region)
	if cloud.ValueString() != cloudAWS || account.ValueString() != "123456789012" || region.ValueString() != "us-east-1" {
		t.Errorf("imported %s %s %s", cloud, account, region)
	}

	for _, id := range []string{"azure/0f8fad5b/eastus", "aws/123456789012/us-east-1", "123456789012", "123456789012/", "/us-east-1"} {
		if resp, ok := importID(id); ok || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "<cloud_account_id>/<region>") {
			t.Errorf("import id %q was accepted", id)
		}
	}
}

func TestStatusReportsOnAWSUnlessToldOtherwiseAndAcceptsNothingElse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusOK, readTestdata(t, "status.json")}})
	var m enforcementStatusDataSourceModel
	if ok, errs := readDataSource(t, &enforcementStatusDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatal(errs)
	}
	if m.Cloud.ValueString() != cloudAWS {
		t.Errorf("cloud reads as %s, want %s", m.Cloud, cloudAWS)
	}
	if !slices.Equal(*requested, []string{"/api/policies/cloudsnapshots/aws/123456789012/us-east-1/status"}) {
		t.Errorf("requested %v", *requested)
	}

	var resp datasource.SchemaResponse
	(&enforcementStatusDataSource{}).Schema(ctx, datasource.SchemaRequest{}, &resp)
	cloud, ok := resp.Schema.Attributes["cloud"].(dsschema.StringAttribute)
	if !ok || !cloud.Optional || !cloud.Computed {
		t.Fatalf("cloud is %#v, want optional", resp.Schema.Attributes["cloud"])
	}
	if cloudIsRefused(ctx, cloud.Validators, "aws") || !cloudIsRefused(ctx, cloud.Validators, "azure") {
		t.Error("cloud must accept aws and only aws")
	}
}

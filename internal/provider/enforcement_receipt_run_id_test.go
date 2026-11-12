package provider

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func receiptObject(t *testing.T, receiptSchema schema.Schema, overrides map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	objectType := receiptSchema.Type().TerraformType(context.Background()).(tftypes.Object)
	ids := tftypes.Map{ElementType: tftypes.String}
	values := map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, "receipt-1"),
		"cloud":            tftypes.NewValue(tftypes.String, cloudAWS),
		"cloud_account_id": tftypes.NewValue(tftypes.String, "123456789012"),
		"region":           tftypes.NewValue(tftypes.String, "us-east-1"),
		"workspace":        tftypes.NewValue(tftypes.String, "enforcement"),
		"snapshot_version": tftypes.NewValue(tftypes.String, "version-1"),
		"security_groups":  tftypes.NewValue(ids, map[string]tftypes.Value{"web": tftypes.NewValue(tftypes.String, "sg-0web")}),
		"rules":            tftypes.NewValue(ids, map[string]tftypes.Value{}),
		"attachments":      tftypes.NewValue(ids, nil),
		"run_id":           tftypes.NewValue(tftypes.String, "run-A"),
		"applied_at":       tftypes.NewValue(tftypes.String, "2026-01-01T00:00:00Z"),
	}
	for name, value := range overrides {
		values[name] = value
	}
	return tftypes.NewValue(objectType, values)
}

// plannedRunID is run_id as an update plan holds it: a computed attribute starts
// unknown in a plan that changes the resource, and its plan modifiers run next.
func plannedRunID(t *testing.T, receiptSchema schema.Schema, prior tftypes.Value) types.String {
	t.Helper()
	ctx := context.Background()
	planned := types.StringUnknown()
	for _, modifier := range receiptSchema.Attributes["run_id"].(schema.StringAttribute).PlanModifiers {
		resp := planmodifier.StringResponse{PlanValue: planned}
		modifier.PlanModifyString(ctx, planmodifier.StringRequest{
			ConfigValue: types.StringNull(),
			PlanValue:   planned,
			StateValue:  types.StringValue("run-A"),
			State:       tfsdk.State{Schema: receiptSchema, Raw: prior},
		}, &resp)
		planned = resp.PlanValue
	}
	return planned
}

// Terraform fails an apply whose result differs from a value its plan already
// held. Every run in HCP Terraform has its own TFC_RUN_ID, so a receipt sent
// again by a later run must not have been planned with the earlier run's.
func TestAReceiptSentAgainByALaterRunRecordsThatRun(t *testing.T) {
	t.Setenv("TFC_RUN_ID", "run-B")
	ctx := context.Background()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/receipts": {http.StatusCreated, `{"receiptId":"receipt-2","appliedAt":"2026-01-02T00:00:00Z"}`},
	})
	receipt := &enforcementReceiptResource{api: api}
	var schemaResp resource.SchemaResponse
	receipt.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	receiptSchema := schemaResp.Schema

	prior := receiptObject(t, receiptSchema, nil)
	planned := plannedRunID(t, receiptSchema, prior)
	plannedValue := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	if !planned.IsUnknown() {
		plannedValue = tftypes.NewValue(tftypes.String, planned.ValueString())
	}
	plan := receiptObject(t, receiptSchema, map[string]tftypes.Value{
		"snapshot_version": tftypes.NewValue(tftypes.String, "version-2"),
		"id":               tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"applied_at":       tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"run_id":           plannedValue,
	})

	resp := resource.UpdateResponse{State: tfsdk.State{Schema: receiptSchema, Raw: prior}}
	receipt.Update(ctx, resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: receiptSchema, Raw: plan},
		State: tfsdk.State{Schema: receiptSchema, Raw: prior},
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("update: %v", resp.Diagnostics)
	}
	var applied enforcementReceiptResourceModel
	if diags := resp.State.Get(ctx, &applied); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	if applied.RunID.ValueString() != "run-B" {
		t.Errorf("run_id %q, want the run that sent the receipt, run-B", applied.RunID.ValueString())
	}
	if !planned.IsUnknown() && !planned.Equal(applied.RunID) {
		t.Errorf("planned run_id %s, applied %s: Terraform fails this apply as an inconsistent result", planned, applied.RunID)
	}
}

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func sentExclusiveRules(t *testing.T, exclusiveRules types.Bool) any {
	t.Helper()
	api, recorder, _ := newSnapshotTestAPI(t, http.StatusCreated, `{"receiptId":"rcpt-1","appliedAt":"2026-01-02T03:04:05Z"}`)
	data := enforcementReceiptResourceModel{
		Cloud: types.StringValue(cloudAWS), CloudAccountID: types.StringValue("111111111111"), Region: types.StringValue("us-east-1"),
		Workspace: types.StringValue("ws"), SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups: types.MapNull(types.StringType), Rules: types.MapNull(types.StringType), Attachments: types.MapNull(types.StringType),
		ExclusiveRules: exclusiveRules,
	}
	var diags diag.Diagnostics
	(&enforcementReceiptResource{api: api}).send(context.Background(), &data, &diags)
	if diags.HasError() || len(recorder.requests) != 1 {
		t.Fatalf("send: %v over %d requests", diags, len(recorder.requests))
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.requests[0].body, &body); err != nil {
		t.Fatal(err)
	}
	sent, ok := body["exclusiveRules"]
	if !ok {
		return nil
	}
	return sent
}

// Xshield words its finding for a rule added by hand from this field: restored by the pipeline when true, removed by
// a person when false. So the receipt always says which.
func TestReceiptBodySaysWhetherGroupsHoldOnlyTheirDeclaredRules(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		set  types.Bool
		want any
	}{
		"true":  {types.BoolValue(true), true},
		"false": {types.BoolValue(false), false},
		"unset": {types.BoolNull(), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := sentExclusiveRules(t, tc.set); got != tc.want {
				t.Errorf("exclusiveRules sent as %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReceiptExclusiveRulesIsOptionalAndFalseByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	attr, ok := receiptSchema(ctx).Attributes["exclusive_rules"].(schema.BoolAttribute)
	if !ok || !attr.Optional || !attr.Computed || attr.Required || attr.Default == nil {
		t.Fatalf("exclusive_rules is %#v, want an optional boolean with a default", attr)
	}
	var byDefault defaults.BoolResponse
	attr.Default.DefaultBool(ctx, defaults.BoolRequest{}, &byDefault)
	if byDefault.PlanValue.IsNull() || byDefault.PlanValue.ValueBool() {
		t.Errorf("exclusive_rules defaults to %s, want false", byDefault.PlanValue)
	}
}

// Turning exclusive rules on or off changes what Xshield says about a hand-added rule, not which receipt it is, so
// the receipt is updated and sent again in place.
func TestChangingExclusiveRulesUpdatesTheReceiptInPlace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := receiptSchema(ctx)
	attr := s.Attributes["exclusive_rules"].(schema.BoolAttribute)
	prior := receiptObject(t, s, nil)
	for _, m := range attr.PlanModifiers {
		var resp planmodifier.BoolResponse
		m.PlanModifyBool(ctx, planmodifier.BoolRequest{
			Path:        path.Root("exclusive_rules"),
			State:       tfsdk.State{Schema: s, Raw: prior},
			Plan:        tfsdk.Plan{Schema: s, Raw: prior},
			StateValue:  types.BoolValue(false),
			PlanValue:   types.BoolValue(true),
			ConfigValue: types.BoolValue(true),
		}, &resp)
		if resp.RequiresReplace {
			t.Fatal("changing exclusive_rules replaces the receipt; want an in-place update")
		}
	}

	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/receipts": {http.StatusCreated, `{"receiptId":"receipt-2","appliedAt":"2026-01-02T00:00:00Z"}`},
	})
	plan := receiptObject(t, s, map[string]tftypes.Value{
		"exclusive_rules": tftypes.NewValue(tftypes.Bool, true),
		"id":              tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"applied_at":      tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"run_id":          tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	})
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: prior}}
	(&enforcementReceiptResource{api: api}).Update(ctx, resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: plan},
		State: tfsdk.State{Schema: s, Raw: prior},
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("update: %v", resp.Diagnostics)
	}
	var before, applied enforcementReceiptResourceModel
	(&tfsdk.State{Schema: s, Raw: prior}).Get(ctx, &before)
	resp.State.Get(ctx, &applied)
	if !applied.ExclusiveRules.ValueBool() || !applied.CloudAccountID.Equal(before.CloudAccountID) || !applied.Region.Equal(before.Region) || !applied.Cloud.Equal(before.Cloud) {
		t.Errorf("after the update the receipt holds %+v, want only exclusive_rules changed from %+v", applied, before)
	}
}

// A receipt in state from before the argument existed reads as false, the value an unset argument plans, so
// upgrading the provider sends no receipt again by itself.
func TestReceiptStateWithoutExclusiveRulesReadsAsFalse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	held := loadJSON[wireConvergence](t, "status.json")
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusOK, readTestdata(t, "status.json")}})
	s := receiptSchema(ctx)
	stored := tfsdk.State{Schema: s}
	model := enforcementReceiptResourceModel{
		ID: types.StringValue(held.Applied.ReceiptID), Cloud: types.StringValue(cloudAWS), CloudAccountID: types.StringValue("111111111111"),
		Region: types.StringValue("us-east-1"), Workspace: types.StringValue("ws"), SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups: types.MapNull(types.StringType), Rules: types.MapNull(types.StringType), Attachments: types.MapNull(types.StringType),
		RunID: types.StringValue(""), AppliedAt: types.StringValue("2026-01-01T00:00:00Z"), ExclusiveRules: types.BoolNull(),
	}
	if diags := stored.Set(ctx, model); diags.HasError() {
		t.Fatal(diags)
	}
	resp := resource.ReadResponse{State: stored}
	(&enforcementReceiptResource{api: api}).Read(ctx, resource.ReadRequest{State: stored}, &resp)
	var exclusiveRules types.Bool
	resp.State.GetAttribute(ctx, path.Root("exclusive_rules"), &exclusiveRules)
	if exclusiveRules.IsNull() || exclusiveRules.ValueBool() {
		t.Errorf("exclusive_rules reads as %s, want false", exclusiveRules)
	}
}

// Rebuilding a lost state takes the value from the receipt Xshield holds, so the plan after recovery sends no
// receipt again for it.
func TestImportedReceiptTakesExclusiveRulesFromTheOneXshieldHolds(t *testing.T) {
	t.Parallel()
	for held, want := range map[string]bool{
		`{"applied":{"receiptId":"rcpt-1","exclusiveRules":true}}`:  true,
		`{"applied":{"receiptId":"rcpt-1","exclusiveRules":false}}`: false,
		`{"applied":{"receiptId":"rcpt-1"}}`:                        false,
	} {
		var status wireConvergence
		if err := json.Unmarshal([]byte(held), &status); err != nil {
			t.Fatal(err)
		}
		var imported enforcementReceiptResourceModel
		var diags diag.Diagnostics
		(&enforcementReceiptResource{}).adopt(context.Background(), &imported, status, &diags)
		if diags.HasError() || imported.ExclusiveRules.IsNull() || imported.ExclusiveRules.ValueBool() != want {
			t.Errorf("held %s: imported exclusive_rules %s, want %v (%v)", held, imported.ExclusiveRules, want, diags)
		}
	}
}

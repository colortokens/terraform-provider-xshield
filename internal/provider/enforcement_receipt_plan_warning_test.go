package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const heldReceiptStatus = `{"state":"converged","applied":{"receiptId":"receipt-1","version":"version-1",` +
	`"workspace":"enforcement-prod","appliedAt":"2026-01-01T00:00:00Z","resources":{}}}`

type receiptPlan struct {
	held     cannedResponse
	inState  bool
	destroy  bool
	planned  map[string]tftypes.Value
	unwired  bool
	wantRead bool
}

// planReceipt plans the receipt as Terraform would and returns the warnings and errors the plan would show.
func planReceipt(t *testing.T, p receiptPlan) (warnings []string, errors int) {
	t.Helper()
	ctx := context.Background()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": p.held})
	receipt := &enforcementReceiptResource{api: api}
	if p.unwired {
		receipt = &enforcementReceiptResource{}
	}
	var schemaResp resource.SchemaResponse
	receipt.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	receiptSchema := schemaResp.Schema
	absent := tftypes.NewValue(receiptSchema.Type().TerraformType(ctx), nil)

	created := map[string]tftypes.Value{
		"id":         tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"run_id":     tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"applied_at": tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	}
	for name, value := range p.planned {
		created[name] = value
	}
	plan, state := receiptObject(t, receiptSchema, created), absent
	if p.inState {
		state = receiptObject(t, receiptSchema, nil)
	}
	if p.destroy {
		plan = absent
	}

	var resp resource.ModifyPlanResponse
	receipt.ModifyPlan(ctx, resource.ModifyPlanRequest{
		Plan:  tfsdk.Plan{Schema: receiptSchema, Raw: plan},
		State: tfsdk.State{Schema: receiptSchema, Raw: state},
	}, &resp)

	if read := len(*requested) > 0; read != p.wantRead {
		t.Errorf("read Xshield's status: %v, want %v (%v)", read, p.wantRead, *requested)
	}
	for _, d := range resp.Diagnostics.Warnings() {
		warnings = append(warnings, d.Summary()+"\n"+d.Detail())
	}
	return warnings, resp.Diagnostics.ErrorsCount()
}

// A second workspace applying to an account and region another already applies to, or one whose state was lost,
// plans to create every group again. The plan is the last place to say so before AWS is changed.
func TestAReceiptAboutToBeCreatedWarnsWhenXshieldAlreadyHoldsOne(t *testing.T) {
	held := cannedResponse{http.StatusOK, heldReceiptStatus}

	t.Run("held by another workspace", func(t *testing.T) {
		warnings, errors := planReceipt(t, receiptPlan{held: held, wantRead: true})
		if errors != 0 || len(warnings) != 1 {
			t.Fatalf("want one warning and no error, got %d error(s) and %q", errors, warnings)
		}
		for _, want := range []string{`"enforcement-prod"`, "2026-01-01T00:00:00Z", "123456789012", "us-east-1", "enforcement-snapshot/recovery"} {
			if !strings.Contains(warnings[0], want) {
				t.Errorf("the warning does not name %s:\n%s", want, warnings[0])
			}
		}
		if strings.Contains(warnings[0], "under this workspace's name") {
			t.Errorf("the warning says the receipt is this workspace's, and it is another's:\n%s", warnings[0])
		}
	})

	t.Run("held under this workspace's name", func(t *testing.T) {
		warnings, _ := planReceipt(t, receiptPlan{held: held, wantRead: true,
			planned: map[string]tftypes.Value{"workspace": tftypes.NewValue(tftypes.String, "enforcement-prod")}})
		if len(warnings) != 1 || !strings.Contains(warnings[0], "under this workspace's name") {
			t.Fatalf("want one warning that the receipt is under this workspace's name, got %q", warnings)
		}
	})

	t.Run("the status cannot be read", func(t *testing.T) {
		warnings, errors := planReceipt(t, receiptPlan{held: cannedResponse{http.StatusForbidden, `{"error":"forbidden"}`}, wantRead: true})
		if errors != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "Cannot check whether Xshield already holds an apply receipt") {
			t.Fatalf("want a plan that goes on and says the check could not be made, got %d error(s) and %q", errors, warnings)
		}
	})

	quiet := map[string]receiptPlan{
		"Xshield holds no receipt":          {held: cannedResponse{http.StatusOK, `{"state":"unapplied"}`}, wantRead: true},
		"the receipt is already in state":   {held: held, inState: true},
		"nothing planned, nothing in state": {held: held, destroy: true},
		"the receipt is being destroyed":    {held: held, inState: true, destroy: true},
		"the provider is not configured":    {held: held, unwired: true},
		"the account is not yet known":      {held: held, planned: map[string]tftypes.Value{"cloud_account_id": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}},
		"the region is not yet known":       {held: held, planned: map[string]tftypes.Value{"region": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}},
		"the receipt held names no holder":  {held: cannedResponse{http.StatusOK, `{"state":"converged","applied":null}`}, wantRead: true},
	}
	for name, plan := range quiet {
		t.Run(name, func(t *testing.T) {
			if warnings, errors := planReceipt(t, plan); errors != 0 || len(warnings) != 0 {
				t.Fatalf("want a plan with nothing added, got %d error(s) and %q", errors, warnings)
			}
		})
	}
}

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

// A receipt Xshield recorded whose answer the apply never got leaves the resources in state and the receipt out of it.
// The next plan sends exactly that receipt again, and must not tell the team its state was lost or another workspace applies.
func TestAHeldReceiptThatIsExactlyThePlannedOneSaysSo(t *testing.T) {
	heldAs := func(resources, exclusive string) cannedResponse {
		return cannedResponse{http.StatusOK, `{"state":"converged","applied":{"receiptId":"receipt-1","version":"version-1",` +
			`"workspace":"enforcement","appliedAt":"2026-01-01T00:00:00Z","resources":` + resources + `,"exclusiveRules":` + exclusive + `}}`}
	}
	same := `{"securityGroups":{"web":"sg-0web"},"rules":{}}`

	t.Run("the same version, workspace, IDs and exclusive_rules", func(t *testing.T) {
		warnings, errors := planReceipt(t, receiptPlan{held: heldAs(same, "false"), wantRead: true})
		if errors != 0 || len(warnings) != 1 {
			t.Fatalf("want one warning and no error, got %d error(s) and %q", errors, warnings)
		}
		for _, want := range []string{"exactly what this plan sends", `"enforcement"`, "2026-01-01T00:00:00Z"} {
			if !strings.Contains(warnings[0], want) {
				t.Errorf("the warning does not say %s:\n%s", want, warnings[0])
			}
		}
		for _, wrong := range []string{"do not apply this one", "rebuild it from that receipt"} {
			if strings.Contains(warnings[0], wrong) {
				t.Errorf("the warning says %q of the receipt this plan sends:\n%s", wrong, warnings[0])
			}
		}
	})

	ids := tftypes.Map{ElementType: tftypes.String}
	differs := map[string]receiptPlan{
		"a rule ID": {held: heldAs(`{"securityGroups":{"web":"sg-0web"},"rules":{"web/in/tcp/443":"sgr-0old"}}`, "false"),
			planned: map[string]tftypes.Value{"rules": tftypes.NewValue(ids, map[string]tftypes.Value{"web/in/tcp/443": tftypes.NewValue(tftypes.String, "sgr-0new")})}},
		"exclusive_rules": {held: heldAs(same, "true")},
		"the workspace":   {held: heldAs(same, "false"), planned: map[string]tftypes.Value{"workspace": tftypes.NewValue(tftypes.String, "enforcement-2")}},
		"the version":     {held: heldAs(same, "false"), planned: map[string]tftypes.Value{"snapshot_version": tftypes.NewValue(tftypes.String, "version-2")}},
		"the group IDs the plan does not know yet": {held: heldAs(same, "false"),
			planned: map[string]tftypes.Value{"security_groups": tftypes.NewValue(ids, tftypes.UnknownValue)}},
		"a group ID the plan does not know yet": {held: heldAs(same, "false"),
			planned: map[string]tftypes.Value{"security_groups": tftypes.NewValue(ids, map[string]tftypes.Value{"web": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})}},
	}
	for name, plan := range differs {
		t.Run(name+" differs", func(t *testing.T) {
			plan.wantRead = true
			warnings, _ := planReceipt(t, plan)
			if len(warnings) != 1 || strings.Contains(warnings[0], "exactly what this plan sends") || !strings.Contains(warnings[0], "enforcement-snapshot/recovery") {
				t.Fatalf("want the lost-state warning, got %q", warnings)
			}
		})
	}
}

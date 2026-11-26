package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const xshieldAccountUnknown = `{"status":404,"code":"accountUnknown","message":"no cloud connector for this subscription"}`

var accountUnknownAnswer = cannedResponse{http.StatusNotFound, xshieldAccountUnknown}

func wantsAccountUnknownError(t *testing.T, what string, ok bool, errs string) {
	t.Helper()
	want := "Xshield does not know subscription " + azureTestSubscription + " for this API key's tenant: check the endpoint and API key"
	if ok || !strings.Contains(errs, want) {
		t.Errorf("%s: ok=%v errors %q, want the plan to fail saying %q", what, ok, errs, want)
	}
}

func errorsOf(diags diag.Diagnostics) string {
	out := []string{}
	for _, d := range diags.Errors() {
		out = append(out, d.Summary()+": "+d.Detail())
	}
	return strings.Join(out, "\n")
}

func TestAzureDataSourcesSayXshieldDoesNotKnowTheSubscription(t *testing.T) {
	t.Parallel()
	_, ok, errs, _ := readAzureSnapshot(t, map[string]cannedResponse{"/expected": accountUnknownAnswer})
	wantsAccountUnknownError(t, "snapshot", ok, errs)

	_, ok, errs, _ = readAzureSecurityRules(t, map[string]cannedResponse{"/status": accountUnknownAnswer}, customerGroupRead(azureTestCustomerGroupID))
	wantsAccountUnknownError(t, "security rules", ok, errs)

	pinned := customerGroupRead(azureTestCustomerGroupID)
	pinned.Version = types.StringValue("v9")
	_, ok, errs, _ = readAzureSecurityRules(t, map[string]cannedResponse{"/versions/v9": accountUnknownAnswer}, pinned)
	wantsAccountUnknownError(t, "security rules at a pinned version", ok, errs)

	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": accountUnknownAnswer})
	var status azureEnforcementStatusDataSourceModel
	ok, errs = readDataSource(t, &azureEnforcementStatusDataSource{api: api}, map[string]tftypes.Value{
		"cloud_account_id": tftypes.NewValue(tftypes.String, azureTestSubscription),
		"region":           tftypes.NewValue(tftypes.String, "eastus2"),
	}, &status)
	wantsAccountUnknownError(t, "status", ok, errs)
}

func TestAzureReceiptSaysXshieldDoesNotKnowTheSubscription(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/receipts": accountUnknownAnswer, "/status": accountUnknownAnswer})
	receipt := &azureEnforcementReceiptResource{api: api}
	s := azureReceiptSchema(ctx)
	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	planned := tfsdk.Plan{Schema: s, Raw: azureReceiptObject(t, s, map[string]tftypes.Value{"id": unknown, "applied_at": unknown, "run_id": unknown})}
	absent := tftypes.NewValue(s.Type().TerraformType(ctx), nil)

	created := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: absent}}
	receipt.Create(ctx, resource.CreateRequest{Plan: planned}, &created)
	wantsAccountUnknownError(t, "create", !created.Diagnostics.HasError(), errorsOf(created.Diagnostics))

	stored := tfsdk.State{Schema: s, Raw: azureReceiptObject(t, s, nil)}
	read := resource.ReadResponse{State: stored}
	receipt.Read(ctx, resource.ReadRequest{State: stored}, &read)
	wantsAccountUnknownError(t, "read", !read.Diagnostics.HasError(), errorsOf(read.Diagnostics))

	var plan resource.ModifyPlanResponse
	receipt.ModifyPlan(ctx, resource.ModifyPlanRequest{Plan: planned, State: tfsdk.State{Schema: s, Raw: absent}}, &plan)
	wantsAccountUnknownError(t, "plan", !plan.Diagnostics.HasError(), errorsOf(plan.Diagnostics))

	imported := resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: absent}}
	receipt.ImportState(ctx, resource.ImportStateRequest{ID: azureTestSubscription + "/eastus2"}, &imported)
	adopted := resource.ReadResponse{State: imported.State}
	receipt.Read(ctx, resource.ReadRequest{State: imported.State}, &adopted)
	wantsAccountUnknownError(t, "import", !adopted.Diagnostics.HasError(), errorsOf(adopted.Diagnostics))
}

func TestAWSSnapshotKeepsItsOwnErrorForA404CodedAccountUnknown(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/expected": accountUnknownAnswer})
	var m awsEnforcementSnapshotDataSourceModel
	ok, errs := readDataSource(t, &awsEnforcementSnapshotDataSource{api: api}, pointArgs(), &m)
	if ok || !strings.Contains(errs, "Cannot resolve the snapshot Xshield expects") || strings.Contains(errs, "does not know subscription") {
		t.Errorf("ok=%v errors %q, want the AWS read's own error", ok, errs)
	}
}

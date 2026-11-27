package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const azurePointPath = "/api/policies/cloudsnapshots/azure/" + azureTestSubscription + "/eastus2"

const azureHeldStatus = `{"state":"converged","expected":{"version":"v1"},"applied":{"receiptId":"rcpt-1","version":"v1",
	"workspace":"enforcement-azure","appliedAt":"2026-11-18T22:40:00Z","exclusiveRules":true,"resources":{"securityGroups":null,"rules":null,
	"networkSecurityGroups":{"ct-policy-web":"/nsg/web"},"subnetAssociations":{"ct-policy-api/snet":"/snet"},
	"interfaceAssociations":{"ct-policy-web/nic":"/nic|/nsg/web"}}},"notices":[]}`

func azureReceiptSchema(ctx context.Context) schema.Schema {
	var resp resource.SchemaResponse
	(&azureEnforcementReceiptResource{}).Schema(ctx, resource.SchemaRequest{}, &resp)
	return resp.Schema
}

func azureReceiptObject(t *testing.T, s schema.Schema, overrides map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	ids := tftypes.Map{ElementType: tftypes.String}
	str := func(v string) tftypes.Value { return tftypes.NewValue(tftypes.String, v) }
	values := map[string]tftypes.Value{
		"id": str("rcpt-1"), "cloud_account_id": str(azureTestSubscription), "region": str("eastus2"),
		"workspace": str("enforcement-azure"), "snapshot_version": str("v1"),
		"network_security_groups": tftypes.NewValue(ids, map[string]tftypes.Value{"ct-policy-web": str("/nsg/web")}),
		"subnet_associations":     tftypes.NewValue(ids, map[string]tftypes.Value{"ct-policy-api/snet": str("/snet")}),
		"interface_associations":  tftypes.NewValue(ids, map[string]tftypes.Value{"ct-policy-web/nic": str("/nic|/nsg/web")}),
		"exclusive_rules":         tftypes.NewValue(tftypes.Bool, true),
		"resend_trigger":          tftypes.NewValue(tftypes.String, nil),
		"run_id":                  str(""), "applied_at": str("2026-11-18T22:40:00Z"),
	}
	for name, value := range overrides {
		values[name] = value
	}
	return tftypes.NewValue(s.Type().TerraformType(context.Background()), values)
}

// The body names each Azure resource as the server's receipt reads it, and no AWS resource.
func TestAzureReceiptSendsTheGroupsAndAssociationsByTheirKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := azureReceiptSchema(ctx)
	var m azureEnforcementReceiptResourceModel
	if diags := (tfsdk.Plan{Schema: s, Raw: azureReceiptObject(t, s, nil)}).Get(ctx, &m); diags.HasError() {
		t.Fatal(diags)
	}
	body, diags := azureReceiptRequest(ctx, &m, "run-1")
	if diags.HasError() {
		t.Fatal(diags)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"v1","workspace":"enforcement-azure","runId":"run-1","resources":{"networkSecurityGroups":{"ct-policy-web":"/nsg/web"},` +
		`"subnetAssociations":{"ct-policy-api/snet":"/snet"},"interfaceAssociations":{"ct-policy-web/nic":"/nic|/nsg/web"}},"exclusiveRules":true}`
	if string(raw) != want {
		t.Errorf("body\n%s\nwant\n%s", raw, want)
	}
}

func TestAzureReceiptRequestsTheAzureEnforcementPoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/receipts": {http.StatusCreated, `{"receiptId":"rcpt-2","appliedAt":"2026-11-18T23:00:00Z"}`},
		"/status":   {http.StatusOK, azureHeldStatus},
	})
	receipt := &azureEnforcementReceiptResource{api: api}
	s := azureReceiptSchema(ctx)
	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	created := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
	receipt.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: s,
		Raw: azureReceiptObject(t, s, map[string]tftypes.Value{"id": unknown, "applied_at": unknown, "run_id": unknown})}}, &created)
	if created.Diagnostics.HasError() {
		t.Fatalf("create: %v", created.Diagnostics)
	}
	var id string
	created.State.GetAttribute(ctx, path.Root("id"), &id)
	if id != "rcpt-2" {
		t.Errorf("id %q, want the receipt Xshield assigned", id)
	}

	stored := tfsdk.State{Schema: s, Raw: azureReceiptObject(t, s, nil)}
	read := resource.ReadResponse{State: stored}
	receipt.Read(ctx, resource.ReadRequest{State: stored}, &read)
	if read.Diagnostics.HasError() || read.Diagnostics.WarningsCount() != 0 || read.State.Raw.IsNull() {
		t.Fatalf("a current receipt read back with %v", read.Diagnostics)
	}

	want := []string{azurePointPath + "/receipts", azurePointPath + "/status"}
	if !slices.Equal(*requested, want) {
		t.Errorf("requested %v, want %v", *requested, want)
	}
}

// A lost state is rebuilt by importing the receipt Xshield holds, with every ID it names.
func TestAzureReceiptImportAdoptsTheReceiptXshieldHolds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": {http.StatusOK, azureHeldStatus}})
	s := azureReceiptSchema(ctx)
	r := &azureEnforcementReceiptResource{api: api}
	imported := resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: azureTestSubscription + "/eastus2"}, &imported)
	if imported.Diagnostics.HasError() {
		t.Fatal(imported.Diagnostics)
	}
	read := resource.ReadResponse{State: imported.State}
	r.Read(ctx, resource.ReadRequest{State: imported.State}, &read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	var m azureEnforcementReceiptResourceModel
	read.State.Get(ctx, &m)
	held := azureReceiptObject(t, s, map[string]tftypes.Value{"run_id": tftypes.NewValue(tftypes.String, "")})
	var want azureEnforcementReceiptResourceModel
	(tfsdk.State{Schema: s, Raw: held}).Get(ctx, &want)
	want.AppliedAt = m.AppliedAt
	if !m.NetworkSecurityGroups.Equal(want.NetworkSecurityGroups) || !m.SubnetAssociations.Equal(want.SubnetAssociations) ||
		!m.InterfaceAssociations.Equal(want.InterfaceAssociations) || m.ID.ValueString() != "rcpt-1" ||
		m.SnapshotVersion.ValueString() != "v1" || !m.ExclusiveRules.ValueBool() {
		t.Errorf("imported %+v, want the held receipt", m)
	}
	var status wireConvergence
	if err := json.Unmarshal([]byte(azureHeldStatus), &status); err != nil {
		t.Fatal(err)
	}
	if !plansHeldAzureReceipt(ctx, *status.Applied, want) {
		t.Error("the held receipt is not recognised as the one a plan of the same resources sends")
	}
}

// resend_trigger only makes Terraform send the receipt again; Xshield's receipt has no place for it.
func TestAzureReceiptDoesNotSendItsResendTrigger(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := azureReceiptSchema(ctx)
	bodyOf := func(overrides map[string]tftypes.Value) string {
		var m azureEnforcementReceiptResourceModel
		if diags := (tfsdk.Plan{Schema: s, Raw: azureReceiptObject(t, s, overrides)}).Get(ctx, &m); diags.HasError() {
			t.Fatal(diags)
		}
		body, diags := azureReceiptRequest(ctx, &m, "")
		if diags.HasError() {
			t.Fatal(diags)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if with, without := bodyOf(map[string]tftypes.Value{"resend_trigger": tftypes.NewValue(tftypes.String, "run-2")}), bodyOf(nil); with != without {
		t.Errorf("resend_trigger changed the body:\n%s\nwant\n%s", with, without)
	}
}

// The module always sets resend_trigger, which an import cannot know, so the first apply after an import sees it change.
// That apply sends nothing when the receipt is otherwise the one imported, and does send one that changes anything else.
func TestAzureReceiptGainingAResendTriggerAfterAnImportIsNotSentAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := azureReceiptSchema(ctx)
	imported := azureReceiptObject(t, s, nil)
	trigger := map[string]tftypes.Value{"resend_trigger": tftypes.NewValue(tftypes.String, "run-2")}
	newVersion := map[string]tftypes.Value{"resend_trigger": tftypes.NewValue(tftypes.String, "run-2"),
		"snapshot_version": tftypes.NewValue(tftypes.String, "v2")}
	for name, test := range map[string]struct {
		planned  map[string]tftypes.Value
		wantSent bool
	}{
		"only the trigger is new":             {planned: trigger},
		"the trigger and the version are new": {planned: newVersion, wantSent: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{
				"/receipts": {http.StatusCreated, `{"receiptId":"rcpt-2","appliedAt":"2026-11-18T23:00:00Z"}`},
			})
			planned := tfsdk.Plan{Schema: s, Raw: azureReceiptObject(t, s, test.planned)}
			updated := resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: imported}}
			(&azureEnforcementReceiptResource{api: api}).Update(ctx, resource.UpdateRequest{Plan: planned,
				State: tfsdk.State{Schema: s, Raw: imported}}, &updated)
			if updated.Diagnostics.HasError() {
				t.Fatal(updated.Diagnostics)
			}
			var id, trigger string
			updated.State.GetAttribute(ctx, path.Root("id"), &id)
			updated.State.GetAttribute(ctx, path.Root("resend_trigger"), &trigger)
			if sent := len(*requested) > 0; sent != test.wantSent || trigger != "run-2" {
				t.Errorf("requested %v, resend_trigger %q; want sent %v and the planned trigger kept", *requested, trigger, test.wantSent)
			}
			if wantID := map[bool]string{true: "rcpt-2", false: "rcpt-1"}[test.wantSent]; id != wantID {
				t.Errorf("id %q, want %q", id, wantID)
			}
		})
	}
}

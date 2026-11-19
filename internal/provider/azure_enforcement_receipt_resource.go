package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &azureEnforcementReceiptResource{}
var _ resource.ResourceWithConfigure = &azureEnforcementReceiptResource{}
var _ resource.ResourceWithImportState = &azureEnforcementReceiptResource{}
var _ resource.ResourceWithModifyPlan = &azureEnforcementReceiptResource{}

func newAzureEnforcementReceiptResource() resource.Resource {
	return &azureEnforcementReceiptResource{}
}

type azureEnforcementReceiptResource struct {
	api cloudSnapshotAPI
}

type azureEnforcementReceiptResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	CloudAccountID        types.String `tfsdk:"cloud_account_id"`
	Region                types.String `tfsdk:"region"`
	Workspace             types.String `tfsdk:"workspace"`
	SnapshotVersion       types.String `tfsdk:"snapshot_version"`
	NetworkSecurityGroups types.Map    `tfsdk:"network_security_groups"`
	SubnetAssociations    types.Map    `tfsdk:"subnet_associations"`
	InterfaceAssociations types.Map    `tfsdk:"interface_associations"`
	ExclusiveRules        types.Bool   `tfsdk:"exclusive_rules"`
	ResendTrigger         types.String `tfsdk:"resend_trigger"`
	RunID                 types.String `tfsdk:"run_id"`
	AppliedAt             types.String `tfsdk:"applied_at"`
}

type wireAzureRenderedResources struct {
	NetworkSecurityGroups map[string]string `json:"networkSecurityGroups"`
	SubnetAssociations    map[string]string `json:"subnetAssociations"`
	InterfaceAssociations map[string]string `json:"interfaceAssociations"`
}

type wireAzureReceipt struct {
	Version        string                     `json:"version"`
	Workspace      string                     `json:"workspace"`
	RunID          string                     `json:"runId,omitempty"`
	Resources      wireAzureRenderedResources `json:"resources"`
	ExclusiveRules bool                       `json:"exclusiveRules"`
}

func (r *azureEnforcementReceiptResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_enforcement_receipt"
}

func (r *azureEnforcementReceiptResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	idMap := func(description string, required bool) schema.MapAttribute {
		return schema.MapAttribute{ElementType: types.StringType, Required: required, Optional: !required, Description: description}
	}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reports to Xshield that an Azure enforcement snapshot has been applied, and which Azure resource " +
			"was created for each key in it. The `azure` enforcement module sends it for you.\n\n" +
			"Place it in the same configuration as the snapshot's resources and reference their IDs, so it is only sent once " +
			"they all exist. Xshield rejects a receipt whose version it did not publish, or whose resources omit or add to the " +
			"snapshot's, so a partial or altered apply is never recorded as converged. An interface association may be left " +
			"out once its network interface is gone.\n\n" +
			"A new receipt is sent only when the applied version, a resource ID, `exclusive_rules` or `resend_trigger` changes. " +
			"Azure gives a network security group or association recreated under the same name its old ID, so an apply that " +
			"restores one changes no ID: `resend_trigger` is how such an apply still sends the receipt, so Xshield observes the " +
			"subscription and region at once rather than at its next drift interval. If Xshield's latest " +
			"receipt for the subscription and region is no longer this one, the next plan proposes sending it again, and a plan " +
			"that creates the receipt while Xshield already holds one warns.\n\n" +
			"Destroying it removes it from state and leaves the receipt history in Xshield.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "Receipt identifier assigned by Xshield."},
			"cloud_account_id": schema.StringAttribute{Required: true, Description: "Azure subscription the snapshot was applied to.",
				PlanModifiers: replace},
			"region": schema.StringAttribute{Required: true, Description: "Azure region the snapshot was applied to.", PlanModifiers: replace},
			"workspace": schema.StringAttribute{Required: true,
				Description: "Name of the enforcement workspace that applied it, as shown in Xshield."},
			"snapshot_version": schema.StringAttribute{Required: true,
				Description: "Version of the snapshot that was applied, from `xshield_azure_enforcement_snapshot`; Xshield accepts a receipt only for a version it published."},
			"network_security_groups": idMap("Network security group ID created for each key in the snapshot's `network_security_groups`.", true),
			"subnet_associations": idMap("The import ID of the association created for each key in the snapshot's `subnet_associations`, "+
				"the subnet's ID.", false),
			"interface_associations": idMap("The import ID of the association created for each key in the snapshot's "+
				"`interface_associations`, `<network interface ID>|<network security group ID>`.", false),
			"exclusive_rules": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Whether each network security group in `network_security_groups` holds only the rules the snapshot " +
					"declares, so the next apply removes a rule added to it outside Terraform. The `azure` enforcement module sets " +
					"it from `enable_exclusive_rules`. Changing it sends the receipt again; it does not replace it."},
			"resend_trigger": schema.StringAttribute{Optional: true,
				Description: "Any value that changes whenever the apply creates, replaces or updates a network security group or " +
					"association the receipt names; a change sends the receipt again and is not itself sent. The `azure` " +
					"enforcement module sets it from a `terraform_data` record replaced on each such change."},
			"run_id": schema.StringAttribute{Computed: true,
				Description: "Run that sent the receipt, taken from `TFC_RUN_ID` when running in HCP Terraform or Terraform Enterprise."},
			"applied_at": schema.StringAttribute{Computed: true, Description: "When Xshield recorded the receipt."},
		},
	}
}

func (r *azureEnforcementReceiptResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*sdk.Xshield)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *sdk.Xshield, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	r.api = cloudSnapshotAPI{client: client}
}

func azureReceiptRequest(ctx context.Context, data *azureEnforcementReceiptResourceModel, runID string) (wireAzureReceipt, diag.Diagnostics) {
	var diags diag.Diagnostics
	ids := func(m types.Map) map[string]string {
		out := map[string]string{}
		if !m.IsNull() {
			diags.Append(m.ElementsAs(ctx, &out, false)...)
		}
		return out
	}
	return wireAzureReceipt{
		Version:   data.SnapshotVersion.ValueString(),
		Workspace: data.Workspace.ValueString(),
		RunID:     runID,
		Resources: wireAzureRenderedResources{
			NetworkSecurityGroups: ids(data.NetworkSecurityGroups),
			SubnetAssociations:    ids(data.SubnetAssociations),
			InterfaceAssociations: ids(data.InterfaceAssociations),
		},
		ExclusiveRules: data.ExclusiveRules.ValueBool(),
	}, diags
}

func azureReceiptAdvice(err error) string {
	var apiErr *snapshotAPIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusUnprocessableEntity:
			return "The resources listed are not exactly the snapshot's: the details name the keys missing or unknown. Create " +
				"every key the snapshot lists, and nothing else, or use the azure enforcement module, which does."
		case http.StatusNotFound:
			return "Xshield published no such version for this subscription and region. Pass snapshot_version from the same " +
				"xshield_azure_enforcement_snapshot the resources were created from."
		case http.StatusConflict:
			if apiErr.Code == codeHandedOver {
				return "This subscription and region's delivery has been handed back to the cloud connector, so this workspace " +
					"no longer delivers its policy: stop applying it. Xshield refuses every receipt from it."
			}
		}
	}
	return "The resources were created; run apply again to send the receipt."
}

func (r *azureEnforcementReceiptResource) send(ctx context.Context, data *azureEnforcementReceiptResourceModel, diags *diag.Diagnostics) {
	runID := os.Getenv("TFC_RUN_ID")
	body, d := azureReceiptRequest(ctx, data, runID)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	var created struct {
		ReceiptID string    `json:"receiptId"`
		AppliedAt time.Time `json:"appliedAt"`
	}
	endpoint := r.api.endpoint(cloudAzure, data.CloudAccountID.ValueString(), data.Region.ValueString(), "receipts")
	if err := r.api.post(ctx, endpoint, body, http.StatusCreated, &created); err != nil {
		diags.AddError("Xshield did not accept the apply receipt", err.Error()+"\n\n"+azureReceiptAdvice(err))
		return
	}
	data.ID = types.StringValue(created.ReceiptID)
	data.AppliedAt = appliedAtValue(&created.AppliedAt)
	data.RunID = types.StringValue(runID)
}

func (r *azureEnforcementReceiptResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data azureEnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.send(ctx, &data, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	}
}

func (r *azureEnforcementReceiptResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data azureEnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.send(ctx, &data, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	}
}

func (r *azureEnforcementReceiptResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data azureEnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var status wireConvergence
	endpoint := r.api.endpoint(cloudAzure, data.CloudAccountID.ValueString(), data.Region.ValueString(), "status")
	if err := r.api.get(ctx, endpoint, &status); err != nil {
		resp.Diagnostics.AddWarning("Cannot confirm Xshield still holds this apply receipt", err.Error())
		return
	}
	if data.ID.IsNull() {
		r.adopt(ctx, &data, status, &resp.Diagnostics)
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		}
		return
	}
	if !receiptIsCurrent(status, data.ID.ValueString()) {
		resp.Diagnostics.AddWarning("Xshield's latest apply receipt is no longer this one",
			"Xshield no longer records this workspace's last apply as the latest for this subscription and region, so the "+
				"receipt will be sent again. If a different workspace is also applying to this subscription and region, "+
				"only one of them should own it.")
		resp.State.RemoveResource(ctx)
	}
}

// ModifyPlan warns before a receipt is created where Xshield already holds one: the state was lost, or another workspace
// applies to the same place.
func (r *azureEnforcementReceiptResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.api.client == nil || req.Plan.Raw.IsNull() || !req.State.Raw.IsNull() {
		return
	}
	var data azureEnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() || data.CloudAccountID.IsUnknown() || data.Region.IsUnknown() {
		return
	}
	var status wireConvergence
	endpoint := r.api.endpoint(cloudAzure, data.CloudAccountID.ValueString(), data.Region.ValueString(), "status")
	if err := r.api.get(ctx, endpoint, &status); err != nil {
		resp.Diagnostics.AddWarning("Cannot check whether Xshield already holds an apply receipt", err.Error())
		return
	}
	if status.Applied == nil {
		return
	}
	where := fmt.Sprintf("subscription %s in %s", data.CloudAccountID.ValueString(), data.Region.ValueString())
	if plansHeldAzureReceipt(ctx, *status.Applied, data) {
		resp.Diagnostics.AddWarning("Xshield already holds the receipt this plan sends", fmt.Sprintf("Xshield's latest receipt for "+
			"%s, sent by workspace %q%s, is exactly what this plan sends. The apply that sent it most likely did not get "+
			"Xshield's answer, so nothing was lost; applying sends it again.", where, status.Applied.Workspace, appliedOn(*status.Applied)))
		return
	}
	resp.Diagnostics.AddWarning("Xshield already holds an apply receipt for this subscription and region", fmt.Sprintf("Xshield "+
		"recorded an apply to %s by workspace %q%s, and this workspace's state does not hold that receipt, so this plan does "+
		"not manage what that apply created. If another workspace applies to this subscription and region, only one should: "+
		"do not apply this one. If this workspace's state was lost, import what that receipt names before applying.",
		where, status.Applied.Workspace, appliedOn(*status.Applied)))
}

func plansHeldAzureReceipt(ctx context.Context, held wireReceipt, planned azureEnforcementReceiptResourceModel) bool {
	if planned.SnapshotVersion.IsUnknown() || planned.Workspace.IsUnknown() || planned.ExclusiveRules.IsUnknown() {
		return false
	}
	sent, diags := azureReceiptRequest(ctx, &planned, "")
	return !diags.HasError() && sent.Version == held.Version && sent.Workspace == held.Workspace &&
		sent.ExclusiveRules == held.ExclusiveRules &&
		maps.Equal(sent.Resources.NetworkSecurityGroups, held.Resources.NetworkSecurityGroups) &&
		maps.Equal(sent.Resources.SubnetAssociations, held.Resources.SubnetAssociations) &&
		maps.Equal(sent.Resources.InterfaceAssociations, held.Resources.InterfaceAssociations)
}

func (r *azureEnforcementReceiptResource) adopt(ctx context.Context, data *azureEnforcementReceiptResourceModel, status wireConvergence, diags *diag.Diagnostics) {
	if status.Applied == nil {
		diags.AddError("Nothing to import", "Xshield holds no apply receipt for this subscription and region yet.")
		return
	}
	a := status.Applied
	toMap := func(m map[string]string) types.Map {
		if m == nil {
			m = map[string]string{}
		}
		v, d := types.MapValueFrom(ctx, types.StringType, m)
		diags.Append(d...)
		return v
	}
	data.ID, data.Workspace, data.SnapshotVersion = types.StringValue(a.ReceiptID), types.StringValue(a.Workspace), types.StringValue(a.Version)
	data.NetworkSecurityGroups = toMap(a.Resources.NetworkSecurityGroups)
	data.SubnetAssociations = toMap(a.Resources.SubnetAssociations)
	data.InterfaceAssociations = toMap(a.Resources.InterfaceAssociations)
	data.ExclusiveRules, data.RunID, data.AppliedAt = types.BoolValue(a.ExclusiveRules), types.StringValue(a.RunID), appliedAtValue(a.AppliedAt)
}

func (r *azureEnforcementReceiptResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// A receipt is a historical record; Xshield keeps it after the resource goes.
}

// ImportState takes "<subscription ID>/<region>" and adopts the receipt Xshield holds for that subscription and region.
func (r *azureEnforcementReceiptResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	account, region, ok := strings.Cut(req.ID, "/")
	if !ok || account == "" || region == "" || strings.Contains(region, "/") {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected <subscription ID>/<region>, got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cloud_account_id"), account)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("region"), region)...)
}

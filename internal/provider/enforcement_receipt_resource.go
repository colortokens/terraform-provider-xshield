package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &EnforcementReceiptResource{}
var _ resource.ResourceWithConfigure = &EnforcementReceiptResource{}
var _ resource.ResourceWithImportState = &EnforcementReceiptResource{}

func NewEnforcementReceiptResource() resource.Resource { return &EnforcementReceiptResource{} }

type EnforcementReceiptResource struct {
	api cloudSnapshotAPI
}

type EnforcementReceiptResourceModel struct {
	ID              types.String `tfsdk:"id"`
	CloudAccountID  types.String `tfsdk:"cloud_account_id"`
	Region          types.String `tfsdk:"region"`
	Workspace       types.String `tfsdk:"workspace"`
	SnapshotVersion types.Int64  `tfsdk:"snapshot_version"`
	ContentHash     types.String `tfsdk:"content_hash"`
	VPCID           types.String `tfsdk:"vpc_id"`
	Groups          types.Map    `tfsdk:"groups"`
	Markers         types.Map    `tfsdk:"markers"`
	PrefixLists     types.Map    `tfsdk:"prefix_lists"`
	Rules           types.Map    `tfsdk:"rules"`
	RunID           types.String `tfsdk:"run_id"`
	AppliedAt       types.String `tfsdk:"applied_at"`
}

func (r *EnforcementReceiptResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_receipt"
}

func (r *EnforcementReceiptResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	idMap := func(description string, required bool) schema.MapAttribute {
		return schema.MapAttribute{ElementType: types.StringType, Required: required, Optional: !required, Description: description}
	}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reports to Xshield that an enforcement snapshot has been applied, and which cloud resource " +
			"was created for each construct in it.\n\n" +
			"Place it in the same configuration as the rendered resources and reference their IDs, so it is only " +
			"sent once they all exist. Xshield rejects a receipt whose hash does not match the snapshot, or whose " +
			"resources omit or add to the snapshot's, so a partial or altered render is never recorded as converged.\n\n" +
			"A new receipt is sent only when the applied version or a resource ID changes, so it adds nothing to a " +
			"plan that has nothing else to do. If Xshield's latest receipt for the account and region is no longer " +
			"this one, the next plan proposes sending it again.\n\n" +
			"Destroying it removes it from state and leaves the receipt history in Xshield.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Receipt identifier assigned by Xshield.",
			},
			"cloud_account_id": schema.StringAttribute{
				Required:      true,
				Description:   "Cloud account the snapshot was applied to.",
				PlanModifiers: replace,
			},
			"region": schema.StringAttribute{
				Required:      true,
				Description:   "Region the snapshot was applied to.",
				PlanModifiers: replace,
			},
			"workspace": schema.StringAttribute{
				Required:    true,
				Description: "Name of the enforcement workspace that applied it, as shown in Xshield.",
			},
			"snapshot_version": schema.Int64Attribute{
				Required:    true,
				Description: "Version of the snapshot that was applied, from `xshield_enforcement_snapshot`.",
			},
			"content_hash": schema.StringAttribute{
				Required:    true,
				Description: "Content hash of the snapshot that was applied, from `xshield_enforcement_snapshot`.",
			},
			"vpc_id": schema.StringAttribute{
				Required:    true,
				Description: "Network the enforcement groups were rendered into.",
			},
			"groups":       idMap("Security group ID created for each enforcement group, keyed by group slug.", true),
			"markers":      idMap("Security group ID created for each marker, keyed by marker slug.", false),
			"prefix_lists": idMap("Prefix list ID created for each named network, keyed by prefix list slug.", false),
			"rules":        idMap("Rule ID created for each snapshot rule, keyed by the snapshot's rule key.", true),
			"run_id": schema.StringAttribute{
				Computed:      true,
				Description:   "Run that sent the receipt, taken from `TFC_RUN_ID` when running in HCP Terraform or Terraform Enterprise.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"applied_at": schema.StringAttribute{
				Computed:    true,
				Description: "When Xshield recorded the receipt.",
			},
		},
	}
}

func (r *EnforcementReceiptResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

type wireRenderedResources struct {
	VPCID       string            `json:"vpcId"`
	Groups      map[string]string `json:"groups"`
	Markers     map[string]string `json:"markers"`
	PrefixLists map[string]string `json:"prefixLists"`
	Rules       map[string]string `json:"rules"`
}

type wireReceipt struct {
	ReceiptID   string                `json:"receiptId,omitempty"`
	Version     int64                 `json:"version"`
	ContentHash string                `json:"contentHash"`
	Workspace   string                `json:"workspace"`
	RunID       string                `json:"runId,omitempty"`
	AppliedAt   string                `json:"appliedAt,omitempty"`
	Resources   wireRenderedResources `json:"resources"`
}

type wireConvergence struct {
	State   string       `json:"state"`
	Applied *wireReceipt `json:"applied"`
}

func receiptRequest(ctx context.Context, data *EnforcementReceiptResourceModel, runID string) (wireReceipt, diag.Diagnostics) {
	var diags diag.Diagnostics
	ids := func(m types.Map) map[string]string {
		out := map[string]string{}
		if !m.IsNull() {
			diags.Append(m.ElementsAs(ctx, &out, false)...)
		}
		return out
	}
	req := wireReceipt{
		Version:     data.SnapshotVersion.ValueInt64(),
		ContentHash: data.ContentHash.ValueString(),
		Workspace:   data.Workspace.ValueString(),
		RunID:       runID,
		Resources: wireRenderedResources{
			VPCID:       data.VPCID.ValueString(),
			Groups:      ids(data.Groups),
			Markers:     ids(data.Markers),
			PrefixLists: ids(data.PrefixLists),
			Rules:       ids(data.Rules),
		},
	}
	return req, diags
}

// receiptIsCurrent is false when Xshield's latest receipt for the enforcement
// point is not this one: Xshield lost it, or another workspace applied since.
func receiptIsCurrent(status wireConvergence, receiptID string) bool {
	return status.Applied != nil && status.Applied.ReceiptID == receiptID
}

func (r *EnforcementReceiptResource) send(ctx context.Context, data *EnforcementReceiptResourceModel, diags *diag.Diagnostics) {
	runID := os.Getenv("TFC_RUN_ID")
	body, d := receiptRequest(ctx, data, runID)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	var created struct {
		ReceiptID string    `json:"receiptId"`
		AppliedAt time.Time `json:"appliedAt"`
	}
	endpoint := r.api.endpoint(data.CloudAccountID.ValueString(), data.Region.ValueString(), "receipts")
	if err := r.api.post(ctx, endpoint, body, http.StatusCreated, &created); err != nil {
		diags.AddError("Xshield did not accept the apply receipt", err.Error())
		return
	}
	data.ID = types.StringValue(created.ReceiptID)
	data.AppliedAt = types.StringValue(created.AppliedAt.UTC().Format(time.RFC3339))
	data.RunID = types.StringValue(runID)
}

func (r *EnforcementReceiptResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data EnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.send(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EnforcementReceiptResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data EnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.send(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EnforcementReceiptResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data EnforcementReceiptResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var status wireConvergence
	endpoint := r.api.endpoint(data.CloudAccountID.ValueString(), data.Region.ValueString(), "status")
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
			"Xshield no longer records this workspace's last apply as the latest for this account and region, so the "+
				"receipt will be sent again. If a different workspace is also applying to this account and region, "+
				"only one of them should own it.")
		resp.State.RemoveResource(ctx)
	}
}

// adopt fills an imported receipt from the one Xshield currently holds, so a
// lost state file can be recovered without sending a new receipt.
func (r *EnforcementReceiptResource) adopt(ctx context.Context, data *EnforcementReceiptResourceModel, status wireConvergence, diags *diag.Diagnostics) {
	if status.Applied == nil {
		diags.AddError("Nothing to import", "Xshield holds no apply receipt for this account and region yet.")
		return
	}
	a := status.Applied
	toMap := func(m map[string]string) types.Map {
		v, d := types.MapValueFrom(ctx, types.StringType, m)
		diags.Append(d...)
		return v
	}
	data.ID = types.StringValue(a.ReceiptID)
	data.Workspace = types.StringValue(a.Workspace)
	data.SnapshotVersion = types.Int64Value(a.Version)
	data.ContentHash = types.StringValue(a.ContentHash)
	data.VPCID = types.StringValue(a.Resources.VPCID)
	data.Groups = toMap(a.Resources.Groups)
	data.Markers = toMap(a.Resources.Markers)
	data.PrefixLists = toMap(a.Resources.PrefixLists)
	data.Rules = toMap(a.Resources.Rules)
	data.RunID = types.StringValue(a.RunID)
	data.AppliedAt = types.StringValue(a.AppliedAt)
}

func (r *EnforcementReceiptResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// A receipt is a historical record; Xshield keeps it after the resource goes.
}

// ImportState takes "<cloud_account_id>/<region>" and adopts the receipt
// Xshield currently holds for it.
func (r *EnforcementReceiptResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	account, region, ok := strings.Cut(req.ID, "/")
	if !ok || account == "" || region == "" {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected <cloud_account_id>/<region>, got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cloud_account_id"), account)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("region"), region)...)
}

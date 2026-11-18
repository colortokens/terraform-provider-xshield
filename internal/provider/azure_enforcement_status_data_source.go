package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &azureEnforcementStatusDataSource{}
var _ datasource.DataSourceWithConfigure = &azureEnforcementStatusDataSource{}

func newAzureEnforcementStatusDataSource() datasource.DataSource {
	return &azureEnforcementStatusDataSource{}
}

type azureEnforcementStatusDataSource struct {
	api cloudSnapshotAPI
}

type azureEnforcementStatusDataSourceModel struct {
	CloudAccountID  types.String  `tfsdk:"cloud_account_id"`
	Region          types.String  `tfsdk:"region"`
	Published       types.Bool    `tfsdk:"published"`
	State           types.String  `tfsdk:"state"`
	ExpectedVersion types.String  `tfsdk:"expected_version"`
	LastCheckedAt   types.String  `tfsdk:"last_checked_at"`
	Notices         []noticeModel `tfsdk:"notices"`
}

func (d *azureEnforcementStatusDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_enforcement_status"
}

func (d *azureEnforcementStatusDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	str := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, Description: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reports the policy Xshield expects for an Azure subscription and region, and what it could not " +
			"enforce there, without changing anything, so it can run inside a `check` block.\n\n" +
			"A workload Xshield refuses is left out of `xshield_azure_enforcement_snapshot` and keeps the network security " +
			"groups it has: the refusal is reported only here, in `notices`, so a plan that changes nothing for a workload " +
			"does not by itself mean its policy is enforced.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, Description: "Azure subscription ID to report on."},
			"region":           schema.StringAttribute{Required: true, Description: "Azure region to report on, such as `eastus2`."},
			"published": schema.BoolAttribute{Computed: true, Description: "False while Xshield has published nothing for this " +
				"subscription and region. `state` is then `unpublished`, `expected_version` is null and `notices` is empty, so checks stay quiet."},
			"state": str("`unapplied` while Xshield has published a snapshot, `unpublished` when it has published nothing to apply, " +
				"and `handedOver` when the subscription moved to connector delivery. Xshield does not yet record applies of an " +
				"Azure snapshot, so a published one reports `unapplied` after an apply too: compare the workspace's " +
				"`xshield_azure_enforcement_snapshot` version with `expected_version` to see whether it is current."),
			"expected_version": str("Version Xshield expects to be enforced, the hash of everything it asks for."),
			"last_checked_at": str("When an enforcement plan last resolved the expected version. A stale value means " +
				"the pipeline has stopped running."),
			"notices": schema.ListAttribute{
				Computed: true,
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"code": types.StringType, "reason": types.StringType, "asset_id": types.StringType, "asset_name": types.StringType, "group": types.StringType,
					"since": types.StringType, "message": types.StringType,
				}},
				MarkdownDescription: "What Xshield could not enforce in the expected version, and why. A refused workload gets no " +
					"network security group of Xshield's and keeps the groups it has, until the cause is fixed. " +
					"`code`: `assetRefused`. " +
					"`reason`: why, such as `NO_FREE_LEVEL` when the workload's network interface and subnet both carry a network " +
					"security group of yours, which its message names, `DISCOVER_FAILED:NO_SUBNET` when discovery shows neither, " +
					"`NOT_EXPRESSIBLE_ON_AZURE:<detail>` when its policy holds a rule no network security rule can hold, or " +
					"`RULE_BUDGET` when its rules, with those of the workloads sharing its group, pass what one group holds. " +
					"`asset_id`: the Xshield asset the notice is about. " +
					"`asset_name`: the workload as Azure names it, when Xshield knows it. " +
					"`group` and `since`: null on Azure. " +
					"`message`: what happened and what to do about it.",
			},
		},
	}
}

func (d *azureEnforcementStatusDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*sdk.Xshield)
	if !ok {
		resp.Diagnostics.AddError("unexpected data source configure type", fmt.Sprintf("expected *sdk.Xshield, got %T", req.ProviderData))
		return
	}
	d.api = cloudSnapshotAPI{client: client}
}

func (d *azureEnforcementStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data azureEnforcementStatusDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}
	var st wireStatus
	err := d.api.get(ctx, d.api.endpoint(cloudAzure, data.CloudAccountID.ValueString(), data.Region.ValueString(), "status"), &st)
	switch {
	case isAPIRefusal(err, http.StatusNotFound, codeNotPublished):
		data.Published, data.State, data.ExpectedVersion = types.BoolValue(false), types.StringValue("unpublished"), types.StringNull()
		data.LastCheckedAt, data.Notices = types.StringNull(), []noticeModel{}
	case err != nil:
		resp.Diagnostics.AddError("failed to read enforcement status", err.Error())
		return
	default:
		data.Published, data.State, data.ExpectedVersion = types.BoolValue(true), types.StringValue(st.State), types.StringValue(st.Expected.Version)
		data.LastCheckedAt, data.Notices = optionalString(st.LastCheckedAt), noticesOf(st.Notices)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func noticesOf(wire []wireNotice) []noticeModel {
	notices := make([]noticeModel, 0, len(wire))
	for _, n := range wire {
		notices = append(notices, noticeModel{Code: types.StringValue(n.Code), Reason: optionalString(n.Reason),
			AssetID: optionalString(n.AssetID), AssetName: optionalString(n.AssetName), Group: optionalString(n.Group), Since: optionalString(n.Since),
			Message: types.StringValue(n.Message)})
	}
	return notices
}

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
	CloudAccountID        types.String        `tfsdk:"cloud_account_id"`
	Region                types.String        `tfsdk:"region"`
	Published             types.Bool          `tfsdk:"published"`
	State                 types.String        `tfsdk:"state"`
	ExpectedVersion       types.String        `tfsdk:"expected_version"`
	AppliedVersion        types.String        `tfsdk:"applied_version"`
	AppliedAt             types.String        `tfsdk:"applied_at"`
	LastCheckedAt         types.String        `tfsdk:"last_checked_at"`
	PendingSince          types.String        `tfsdk:"pending_since"`
	Notices               []noticeModel       `tfsdk:"notices"`
	AppliedGroups         types.Map           `tfsdk:"applied_network_security_groups"`
	AppliedSubnetAssocs   types.Map           `tfsdk:"applied_subnet_associations"`
	AppliedInterfaceAssoc types.Map           `tfsdk:"applied_interface_associations"`
	DriftEvaluated        types.Bool          `tfsdk:"drift_evaluated"`
	DriftObservedAt       types.String        `tfsdk:"drift_observed_at"`
	DriftFindings         []driftFindingModel `tfsdk:"drift_findings"`
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
			"state": str("`converged` when the latest receipt is for the expected version, `pending` when Xshield expects newer " +
				"policy than was applied, `unapplied` when nothing has been applied yet, `unpublished` when Xshield has published " +
				"nothing to apply, and `handedOver` when the subscription moved to connector delivery."),
			"expected_version": str("Version Xshield expects to be enforced, the hash of everything it asks for."),
			"applied_version":  str("Version in the latest apply receipt. Null when nothing has been applied."),
			"applied_at":       str("When the latest receipt was recorded."),
			"last_checked_at": str("When an enforcement plan last resolved the expected version. A stale value means " +
				"the pipeline has stopped running, whatever `state` says."),
			"pending_since":                   str("When the oldest policy change not yet applied was published."),
			"applied_network_security_groups": appliedIDs("network security group ID", "`azurerm_network_security_group.this`"),
			"applied_subnet_associations": appliedIDs("subnet association import ID, the subnet's ID",
				"`azurerm_subnet_network_security_group_association.this`"),
			"applied_interface_associations": appliedIDs("interface association import ID, `<network interface ID>|<network security group ID>`",
				"`azurerm_network_interface_security_group_association.this`"),
			"drift_evaluated": schema.BoolAttribute{Computed: true, Description: "Whether drift could be evaluated: it " +
				"needs an applied receipt and a cloud connector observation taken after it. An observation older than the " +
				"latest apply describes resources that apply replaced, so it is not evaluated."},
			"drift_observed_at": str("When the cloud connector's latest observation was taken."),
			"drift_findings": schema.ListAttribute{
				Computed: true,
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"kind": types.StringType, "severity": types.StringType, "restoration": types.StringType,
					"resource": types.StringType, "resource_name": types.StringType, "key": types.StringType, "detail": types.StringType,
					"detected_at": types.StringType,
				}},
				MarkdownDescription: "Differences between the subscription as observed and the snapshot as applied. " +
					"`kind`: `groupMissing` when a network security group of Xshield's is gone, `ruleMissing` or `ruleModified` when " +
					"one of its rules is gone or no longer matches, `ruleUnmanaged` when a group holds a rule named as Xshield names " +
					"its rules, or any rule once the latest receipt set `exclusive_rules`, that the snapshot does not hold, " +
					"`memberUnattached` when a workload's network interface or subnet no longer carries its group, and " +
					"`groupUnmanaged` when a network security group carries the pipeline's tags but the applied state does not hold it. " +
					"`severity`: `high` where access may be wider than approved or a workload is unenforced, otherwise `medium`. " +
					"`restoration`: `pipeline` when the next enforcement apply restores it, `manual` for `groupUnmanaged`, " +
					"which Terraform cannot see and must be removed by hand. " +
					"`resource`: Azure resource ID of the affected group or rule, or the Xshield asset ID for `memberUnattached`. " +
					"`resource_name`: the group's key for `groupMissing`, the rule's name for a rule finding, the group's name for `groupUnmanaged`. " +
					"`key`: snapshot key involved: the group's key in `xshield_azure_enforcement_snapshot`, or `<group key>/<rule name>` for a missing or changed rule. " +
					"`detail`: human-readable explanation. " +
					"`detected_at`: when Xshield recorded the finding, which stays recorded until an observation shows it gone; null " +
					"for a state the next enforcement apply clears or makes, which Xshield does not record as drift.",
			},
			"notices": schema.ListAttribute{
				Computed: true,
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"code": types.StringType, "reason": types.StringType, "asset_id": types.StringType, "asset_name": types.StringType, "group": types.StringType,
					"since": types.StringType, "message": types.StringType,
				}},
				MarkdownDescription: "What Xshield could not enforce in the expected version, and why. A refused workload gets no " +
					"network security group of Xshield's and keeps the groups it has, until the cause is fixed. " +
					"`reason`: why, such as `NO_FREE_LEVEL` when the workload's network interface and subnet both carry a network " +
					"security group of yours, which its message names, `INTERFACES_IN_SEVERAL_SUBNETS` when its network interfaces " +
					"are in more than one subnet and one carries a group of yours, so no one subnet would cover them all, " +
					"`DISCOVER_FAILED:NO_SUBNET` when discovery shows neither, " +
					"`NOT_EXPRESSIBLE_ON_AZURE:<detail>` when its policy holds a rule no network security rule can hold, " +
					"`RULE_BUDGET` when its rules, with those of the workloads sharing its group, pass what one group holds, " +
					"`ENDPOINT_NETWORK_POLICIES_OFF` when it is reached through a private endpoint whose subnet's private endpoint " +
					"network policies are neither `Enabled` nor `NetworkSecurityGroupEnabled`, so a group there would not filter its " +
					"traffic, `NO_PRIVATE_INBOUND` when a Function App with inbound policy has no private endpoint, " +
					"`INTEGRATION_SUBNET_SHARED` when a Function App with outbound policy shares its VNet integration subnet with " +
					"other apps, or `DISCOVER_FAILED:NO_INTEGRATION_SUBNET_RANGE` when discovery gives no address range of that subnet. " +
					"An `observationStale` notice is about the subscription and region: the cloud connector has not observed them for three " +
					"observation intervals since the last apply or observation, so a change made in Azure since is not shown as drift. " +
					"An `associationHeld` notice names a group of Xshield's that this version no longer places, whose network " +
					"interface or subnet the cloud connector has shown carrying a network security group of yours since the last " +
					"apply. Azure removes an association by clearing its level's group, so removing Xshield's would remove yours: " +
					"the `azure` enforcement module keeps it in its state, unchanged, until the level carries no group of yours. " +
					"An `assetContained` notice names a workload the cloud connector contains: its group is on the workload's network " +
					"interface or subnet in place of Xshield's, and the module keeps Xshield's association as it is until the " +
					"containment is reverted. A `levelSharedWithContained` notice names a workload whose subnet a contained workload " +
					"shares, so the connector's group covers it too and it is not synchronized until the containment is reverted. " +
					"A `customerGroupWritten` notice names a workload whose every network interface and subnet carries a group of " +
					"yours, so Xshield writes its rules into your subnet's group, which `group` names. A `connectorHandsOver` notice " +
					"names a workload the cloud connector enforced with a group of its own, which `group` names: once this version is " +
					"applied, the connector puts Xshield's group, or the group of yours its own displaced, in place of its group, and " +
					"then removes its group. " +
					"`code`: `assetRefused`, `assetContained`, `levelSharedWithContained`, `customerGroupWritten`, `connectorHandsOver`, " +
					"`associationHeld` or `observationStale`. " +
					"`asset_id`: the Xshield asset the notice is about, when there is one. " +
					"`asset_name`: the workload as Azure names it, when Xshield knows it. " +
					"`group`: for `associationHeld`, the group by its key in the snapshot; for `customerGroupWritten`, the name of your " +
					"group; for `connectorHandsOver`, the name of the cloud connector's group; null for every other code. " +
					"`since`: for `observationStale`, the last apply or observation it counts from; null for every other code. " +
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
	case isAzureAccountUnknown(err):
		addAzureAccountUnknownError(&resp.Diagnostics, data.CloudAccountID.ValueString(), err)
		return
	case isAPIRefusal(err, http.StatusNotFound, codeNotPublished):
		st = wireStatus{State: "unpublished"}
		data.Published, data.ExpectedVersion = types.BoolValue(false), types.StringNull()
	case err != nil:
		resp.Diagnostics.AddError("failed to read enforcement status", err.Error())
		return
	default:
		data.Published, data.ExpectedVersion = types.BoolValue(true), types.StringValue(st.Expected.Version)
	}
	data.State, data.LastCheckedAt, data.PendingSince = types.StringValue(st.State), optionalString(st.LastCheckedAt), optionalString(st.PendingSince)
	data.Notices = noticesOf(st.Notices)
	data.AppliedVersion, data.AppliedAt = types.StringNull(), types.StringNull()
	applied := wireRenderedResources{}
	if st.Applied != nil {
		data.AppliedVersion, data.AppliedAt, applied = types.StringValue(st.Applied.Version), appliedAtValue(st.Applied.AppliedAt), st.Applied.Resources
	}
	data.AppliedGroups, data.AppliedSubnetAssocs = stringMap(applied.NetworkSecurityGroups), stringMap(applied.SubnetAssociations)
	data.AppliedInterfaceAssoc = stringMap(applied.InterfaceAssociations)
	data.DriftEvaluated, data.DriftObservedAt, data.DriftFindings = types.BoolValue(false), types.StringNull(), []driftFindingModel{}
	if st.Drift != nil {
		data.DriftEvaluated, data.DriftObservedAt = types.BoolValue(!st.Drift.ObservationStale), optionalString(st.Drift.ObservedAt)
		data.DriftFindings = driftFindingsOf(*st.Drift)
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

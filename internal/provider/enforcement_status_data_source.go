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

var _ datasource.DataSource = &enforcementStatusDataSource{}
var _ datasource.DataSourceWithConfigure = &enforcementStatusDataSource{}

func newEnforcementStatusDataSource() datasource.DataSource {
	return &enforcementStatusDataSource{}
}

// enforcementStatusDataSource reports what Xshield knows about an enforcement
// point without changing anything, so it can run inside a check block that is
// evaluated when no apply is happening.
type enforcementStatusDataSource struct {
	api cloudSnapshotAPI
}

type driftFindingModel struct {
	Kind         types.String `tfsdk:"kind"`
	Severity     types.String `tfsdk:"severity"`
	Restoration  types.String `tfsdk:"restoration"`
	Resource     types.String `tfsdk:"resource"`
	ResourceName types.String `tfsdk:"resource_name"`
	Key          types.String `tfsdk:"key"`
	Detail       types.String `tfsdk:"detail"`
}

type noticeModel struct {
	Code      types.String `tfsdk:"code"`
	Reason    types.String `tfsdk:"reason"`
	AssetID   types.String `tfsdk:"asset_id"`
	AssetName types.String `tfsdk:"asset_name"`
	Group     types.String `tfsdk:"group"`
	Message   types.String `tfsdk:"message"`
}

type enforcementStatusDataSourceModel struct {
	CloudAccountID      types.String        `tfsdk:"cloud_account_id"`
	Region              types.String        `tfsdk:"region"`
	Published           types.Bool          `tfsdk:"published"`
	State               types.String        `tfsdk:"state"`
	ExpectedVersion     types.String        `tfsdk:"expected_version"`
	AppliedVersion      types.String        `tfsdk:"applied_version"`
	AppliedAt           types.String        `tfsdk:"applied_at"`
	LastCheckedAt       types.String        `tfsdk:"last_checked_at"`
	PendingSince        types.String        `tfsdk:"pending_since"`
	PendingRulesAdded   []types.String      `tfsdk:"pending_rules_added"`
	PendingRulesRemoved []types.String      `tfsdk:"pending_rules_removed"`
	PendingGroups       []types.String      `tfsdk:"pending_security_groups_added"`
	PendingAttachments  []types.String      `tfsdk:"pending_attachments_added"`
	Notices             []noticeModel       `tfsdk:"notices"`
	DriftEvaluated      types.Bool          `tfsdk:"drift_evaluated"`
	DriftObservedAt     types.String        `tfsdk:"drift_observed_at"`
	DriftFindings       []driftFindingModel `tfsdk:"drift_findings"`
	AppliedGroups       types.Map           `tfsdk:"applied_security_groups"`
	AppliedRules        types.Map           `tfsdk:"applied_rules"`
	AppliedAttachments  types.Map           `tfsdk:"applied_attachments"`
	HandOverGroups      types.Map           `tfsdk:"handover_security_groups"`
	HandOverRules       types.Map           `tfsdk:"handover_rules"`
	HandOverAttachments types.Map           `tfsdk:"handover_attachments"`
}

func (d *enforcementStatusDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_status"
}

func (d *enforcementStatusDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	str := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, Description: description}
	}
	strList := func(description string) schema.ListAttribute {
		return schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reports whether an account and region have converged on the policy Xshield expects, what the " +
			"next enforcement run would change, and what the cloud connector observes that differs from what was applied.\n\n" +
			"It reads only, so it can run inside a `check` block. Where checks are evaluated on a schedule, such as HCP " +
			"Terraform continuous validation, that alerts on drift and stalled pipelines without anyone running an apply.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, Description: "Cloud account to report on."},
			"region":           schema.StringAttribute{Required: true, Description: "Region to report on."},
			"published": schema.BoolAttribute{Computed: true, Description: "False while Xshield has published nothing for this " +
				"account and region. `state` is then `unpublished`, versions are null and every list is empty, so checks stay quiet."},
			"state": str("`converged` when the latest receipt matches the expected snapshot, `waiting` when it does but a " +
				"Full control change still waits on another workspace's apply or on discovery, which its `changeSetHeld` notices " +
				"name, `pending` when Xshield expects newer policy than was applied, `unapplied` when nothing has been applied " +
				"yet, `unpublished` when Xshield has published nothing to apply, `handedOver` when the account moved to connector " +
				"delivery, and the cloud connector keeps the groups the pipeline created."),
			"expected_version": str("Version Xshield expects to be enforced, the hash of everything it asks for."),
			"applied_version":  str("Version in the latest apply receipt. Null when nothing has been applied."),
			"applied_at":       str("When the latest receipt was recorded."),
			"last_checked_at": str("When an enforcement plan last resolved the expected version. A stale value means " +
				"the pipeline has stopped running, whatever the convergence state says."),
			"pending_since":                 str("When the oldest policy change not yet applied was published."),
			"pending_rules_added":           strList("Keys of rules the next enforcement run will add."),
			"pending_rules_removed":         strList("Keys of rules the next enforcement run will remove."),
			"pending_security_groups_added": strList("Keys of security groups the next enforcement run will create."),
			"pending_attachments_added":     strList("Keys of interface attachments the next enforcement run will create."),
			"notices": schema.ListAttribute{
				Computed: true,
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"code": types.StringType, "reason": types.StringType, "asset_id": types.StringType, "asset_name": types.StringType, "group": types.StringType, "message": types.StringType,
				}},
				MarkdownDescription: "What Xshield could not enforce in the latest version, and why. A refusal leaves a workload " +
					"as it was: one that carries an Xshield group keeps it, with the rules last applied, and one that carries " +
					"none gets none until the cause is fixed. A contained workload's group stays off its interfaces until the " +
					"containment is reverted. A `groupRefused` group that fits once changed, but not while it changes, is the " +
					"one exception: the rules its change removes and no new rule replaces come out first, and its new rules " +
					"go in at the next apply if they then fit. " +
					"`code`: `assetRefused`, `assetContained`, `groupRefused`, `withdrawing` or `changeSetHeld`. " +
					"`reason`: the cloud connector's refusal code, as the Xshield portal shows it, such as `NO_FREE_SLOT` or `RULE_BUDGET_EXCEEDED:inbound/ipv4=61`, or for `changeSetHeld` the change set's ID. " +
					"`asset_id`, `group`: the Xshield asset, or the security group key, the notice is about, when there is one. " +
					"`asset_name`: the asset as AWS names it, its instance ID or its handle, such as `rds/orders-db`. " +
					"`message`: what happened and what it means for the workload.",
			},
			"applied_security_groups": appliedIDs("security group ID", "`aws_security_group.this`"),
			"applied_rules": appliedIDs("security group rule ID", "`aws_vpc_security_group_ingress_rule.this`, for a key with `/in/`, or "+
				"`aws_vpc_security_group_egress_rule.this`, for a key with `/out/`"),
			"applied_attachments": appliedIDs("attachment import ID, `<network interface ID>_<security group ID>`",
				"`aws_network_interface_sg_attachment.this`"),
			"handover_security_groups": handOverIDs("security group ID", "`aws_security_group.this`"),
			"handover_rules": handOverIDs("security group rule ID", "`aws_vpc_security_group_ingress_rule.this`, for a key with `/in/`, or "+
				"`aws_vpc_security_group_egress_rule.this`, for a key with `/out/`"),
			"handover_attachments": handOverIDs("attachment import ID, `<network interface ID>_<security group ID>`",
				"`aws_network_interface_sg_attachment.this`"),
			"drift_evaluated": schema.BoolAttribute{Computed: true, Description: "Whether drift could be evaluated: it " +
				"needs an applied receipt and a cloud connector observation taken after it. An observation older than the " +
				"latest apply describes resources that apply replaced, so it is not evaluated."},
			"drift_observed_at": str("When the cloud connector's latest observation was taken."),
			"drift_findings": schema.ListAttribute{
				Computed: true,
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"kind": types.StringType, "severity": types.StringType, "restoration": types.StringType,
					"resource": types.StringType, "resource_name": types.StringType, "key": types.StringType, "detail": types.StringType,
				}},
				MarkdownDescription: "Differences between the cloud as observed and the snapshot as applied. " +
					"`kind`: what differs, such as `ruleMissing`, `ruleUnmanaged` or `memberUnattached`. " +
					"`severity`: `high` where access may be wider than approved or a workload is unenforced, otherwise `medium`. " +
					"`restoration`: `pipeline` when the next enforcement apply restores it, `manual` when Terraform cannot see it " +
					"and it must be removed by hand, `workload` when the owning workspace's attachment must change. " +
					"`resource`: AWS ID of the affected resource, or the Xshield asset ID for an attachment finding. " +
					"`resource_name`: for an attachment finding, the workload as AWS names it, its instance ID or its handle. " +
					"`key`: snapshot key involved, when there is one. " +
					"`detail`: human-readable explanation.",
			},
		},
	}
}

func (d *enforcementStatusDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type wireStatus struct {
	State    string `json:"state"`
	Expected struct {
		Version string `json:"version"`
	} `json:"expected"`
	Applied       *wireReceipt `json:"applied"`
	LastCheckedAt string       `json:"lastCheckedAt"`
	PendingSince  string       `json:"pendingSince"`
	PendingDelta  *struct {
		SecurityGroupsAdded []string `json:"securityGroupsAdded"`
		RulesAdded          []string `json:"rulesAdded"`
		RulesRemoved        []string `json:"rulesRemoved"`
		AttachmentsAdded    []string `json:"attachmentsAdded"`
	} `json:"pendingDelta"`
	Notices []struct {
		Code      string `json:"code"`
		Reason    string `json:"reason"`
		AssetID   string `json:"assetId"`
		AssetName string `json:"assetName"`
		Group     string `json:"group"`
		Message   string `json:"message"`
	} `json:"notices"`
	Drift    *wireDrift             `json:"drift"`
	HandOver *wireRenderedResources `json:"handOver"`
}

type wireDrift struct {
	ObservedAt       string `json:"observedAt"`
	ObservationStale bool   `json:"observationStale"`
	Findings         []struct {
		Kind         string `json:"kind"`
		Severity     string `json:"severity"`
		Restoration  string `json:"restoration"`
		Resource     string `json:"resource"`
		ResourceName string `json:"resourceName"`
		Key          string `json:"key"`
		Detail       string `json:"detail"`
	} `json:"findings"`
}

func (d *enforcementStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data enforcementStatusDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}
	account, region := data.CloudAccountID.ValueString(), data.Region.ValueString()

	data.DriftFindings = []driftFindingModel{}
	data.DriftEvaluated = types.BoolValue(false)
	data.DriftObservedAt = types.StringNull()
	var st wireStatus
	err := d.api.get(ctx, d.api.endpoint(cloudAWS, account, region, "status"), &st)
	if isAPIRefusal(err, http.StatusNotFound, codeNotPublished) {
		setUnpublished(&data)
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("failed to read enforcement status", err.Error())
		return
	}
	setStatus(&data, st)
	if st.Drift != nil {
		setDrift(&data, *st.Drift)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// appliedIDs lets a lost state be rebuilt from the last receipt with import blocks keyed as the module keys its resources.
func appliedIDs(what, resource string) schema.MapAttribute {
	return schema.MapAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "From the last receipt: the " +
		what + " of each resource the enforcement module created, keyed as the module keys " + resource + ". Empty before the first receipt."}
}

func handOverIDs(what, resource string) schema.MapAttribute {
	return schema.MapAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Before the first receipt of an " +
		"account moved from connector delivery: the " + what + " of each resource the cloud connector created that the expected " +
		"snapshot names, keyed as the module keys " + resource + ", so the enforcement workspace imports it rather than creating it " +
		"again. Empty otherwise."}
}

func stringMap(m map[string]string) types.Map {
	values := make(map[string]attr.Value, len(m))
	for k, v := range m {
		values[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, values)
}

func setUnpublished(data *enforcementStatusDataSourceModel) {
	setStatus(data, wireStatus{State: "unpublished"})
	data.Published = types.BoolValue(false)
	data.ExpectedVersion = types.StringNull()
}

func setStatus(data *enforcementStatusDataSourceModel, st wireStatus) {
	data.Published = types.BoolValue(true)
	data.State = types.StringValue(st.State)
	data.ExpectedVersion = types.StringValue(st.Expected.Version)
	data.AppliedVersion, data.AppliedAt = types.StringNull(), types.StringNull()
	applied := wireRenderedResources{}
	if st.Applied != nil {
		data.AppliedVersion = types.StringValue(st.Applied.Version)
		data.AppliedAt = appliedAtValue(st.Applied.AppliedAt)
		applied = st.Applied.Resources
	}
	data.AppliedGroups, data.AppliedRules, data.AppliedAttachments = stringMap(applied.SecurityGroups), stringMap(applied.Rules), stringMap(applied.Attachments)
	handOver := wireRenderedResources{}
	if st.HandOver != nil {
		handOver = *st.HandOver
	}
	data.HandOverGroups, data.HandOverRules, data.HandOverAttachments = stringMap(handOver.SecurityGroups), stringMap(handOver.Rules), stringMap(handOver.Attachments)
	data.LastCheckedAt = optionalString(st.LastCheckedAt)
	data.PendingSince = optionalString(st.PendingSince)
	data.PendingRulesAdded, data.PendingRulesRemoved, data.PendingGroups, data.PendingAttachments = []types.String{}, []types.String{}, []types.String{}, []types.String{}
	if st.PendingDelta != nil {
		data.PendingRulesAdded = toStrList(st.PendingDelta.RulesAdded)
		data.PendingRulesRemoved = toStrList(st.PendingDelta.RulesRemoved)
		data.PendingGroups = toStrList(st.PendingDelta.SecurityGroupsAdded)
		data.PendingAttachments = toStrList(st.PendingDelta.AttachmentsAdded)
	}
	data.Notices = []noticeModel{}
	for _, n := range st.Notices {
		data.Notices = append(data.Notices, noticeModel{Code: types.StringValue(n.Code), Reason: optionalString(n.Reason),
			AssetID: optionalString(n.AssetID), AssetName: optionalString(n.AssetName), Group: optionalString(n.Group), Message: types.StringValue(n.Message)})
	}
}

func setDrift(data *enforcementStatusDataSourceModel, drift wireDrift) {
	data.DriftEvaluated = types.BoolValue(!drift.ObservationStale)
	data.DriftObservedAt = optionalString(drift.ObservedAt)
	for _, f := range drift.Findings {
		data.DriftFindings = append(data.DriftFindings, driftFindingModel{
			Kind: types.StringValue(f.Kind), Severity: types.StringValue(f.Severity), Restoration: types.StringValue(f.Restoration),
			Resource: types.StringValue(f.Resource), ResourceName: optionalString(f.ResourceName), Key: optionalString(f.Key), Detail: types.StringValue(f.Detail),
		})
	}
}

func optionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

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

var _ datasource.DataSource = &EnforcementStatusDataSource{}
var _ datasource.DataSourceWithConfigure = &EnforcementStatusDataSource{}

func NewEnforcementStatusDataSource() datasource.DataSource {
	return &EnforcementStatusDataSource{}
}

// EnforcementStatusDataSource reports what Xshield knows about an enforcement
// point without changing anything, so it can run inside a check block that is
// evaluated when no apply is happening.
type EnforcementStatusDataSource struct {
	api cloudSnapshotAPI
}

type driftFindingModel struct {
	Kind        types.String `tfsdk:"kind"`
	Severity    types.String `tfsdk:"severity"`
	Restoration types.String `tfsdk:"restoration"`
	Resource    types.String `tfsdk:"resource"`
	Key         types.String `tfsdk:"key"`
	Detail      types.String `tfsdk:"detail"`
}

type noticeModel struct {
	Code    types.String `tfsdk:"code"`
	Reason  types.String `tfsdk:"reason"`
	AssetID types.String `tfsdk:"asset_id"`
	Group   types.String `tfsdk:"group"`
	Message types.String `tfsdk:"message"`
}

type EnforcementStatusDataSourceModel struct {
	CloudAccountID      types.String        `tfsdk:"cloud_account_id"`
	Region              types.String        `tfsdk:"region"`
	Published           types.Bool          `tfsdk:"published"`
	State               types.String        `tfsdk:"state"`
	ExpectedVersion     types.Int64         `tfsdk:"expected_version"`
	ExpectedContentHash types.String        `tfsdk:"expected_content_hash"`
	AppliedVersion      types.Int64         `tfsdk:"applied_version"`
	AppliedContentHash  types.String        `tfsdk:"applied_content_hash"`
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
}

func (d *EnforcementStatusDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_status"
}

func (d *EnforcementStatusDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
			"state": str("`converged` when the latest receipt matches the expected snapshot, `pending` when Xshield " +
				"expects newer policy than was applied, `unapplied` when nothing has been applied yet, `unpublished` when " +
				"Xshield has published nothing to apply."),
			"expected_version":      schema.Int64Attribute{Computed: true, Description: "Version Xshield expects to be enforced."},
			"expected_content_hash": str("Content hash of the expected snapshot."),
			"applied_version":       schema.Int64Attribute{Computed: true, Description: "Version in the latest apply receipt. Null when nothing has been applied."},
			"applied_content_hash":  str("Content hash in the latest apply receipt."),
			"applied_at":            str("When the latest receipt was recorded."),
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
					"code": types.StringType, "reason": types.StringType, "asset_id": types.StringType, "group": types.StringType, "message": types.StringType,
				}},
				MarkdownDescription: "What Xshield could not enforce in the latest version, and why. A workload with a refusal " +
					"carries no Xshield group until the cause is fixed. " +
					"`code`: `assetRefused`, `assetContained`, `groupRefused` or `withdrawing`. " +
					"`reason`: the cloud connector's refusal code, as the Xshield portal shows it, such as `NO_FREE_SLOT` or `RULE_BUDGET_EXCEEDED:inbound/ipv4=61`. " +
					"`asset_id`, `group`: the Xshield asset, or the security group key, the notice is about, when there is one. " +
					"`message`: what happened and what it means for the workload.",
			},
			"drift_evaluated": schema.BoolAttribute{Computed: true, Description: "Whether drift could be evaluated: it " +
				"needs an applied receipt and a cloud connector observation taken after it. An observation older than the " +
				"latest apply describes resources that apply replaced, so it is not evaluated."},
			"drift_observed_at": str("When the cloud connector's latest observation was taken."),
			"drift_findings": schema.ListAttribute{
				Computed: true,
				ElementType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"kind": types.StringType, "severity": types.StringType, "restoration": types.StringType,
					"resource": types.StringType, "key": types.StringType, "detail": types.StringType,
				}},
				MarkdownDescription: "Differences between the cloud as observed and the snapshot as applied. " +
					"`kind`: what differs, such as `ruleMissing`, `ruleUnmanaged` or `memberUnattached`. " +
					"`severity`: `high` where access may be wider than approved or a workload is unenforced, otherwise `medium`. " +
					"`restoration`: `pipeline` when the next enforcement apply restores it, `manual` when Terraform cannot see it " +
					"and it must be removed by hand, `workload` when the owning workspace's attachment must change. " +
					"`resource`: AWS ID of the affected resource, or the Xshield asset ID for an attachment finding. " +
					"`key`: snapshot key involved, when there is one. " +
					"`detail`: human-readable explanation.",
			},
		},
	}
}

func (d *EnforcementStatusDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
		Version     int64  `json:"version"`
		ContentHash string `json:"contentHash"`
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
		Code    string `json:"code"`
		Reason  string `json:"reason"`
		AssetID string `json:"assetId"`
		Group   string `json:"group"`
		Message string `json:"message"`
	} `json:"notices"`
}

type wireDrift struct {
	ObservedAt       string `json:"observedAt"`
	ObservationStale bool   `json:"observationStale"`
	Findings         []struct {
		Kind        string `json:"kind"`
		Severity    string `json:"severity"`
		Restoration string `json:"restoration"`
		Resource    string `json:"resource"`
		Key         string `json:"key"`
		Detail      string `json:"detail"`
	} `json:"findings"`
}

func (d *EnforcementStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data EnforcementStatusDataSourceModel
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
	err := d.api.get(ctx, d.api.endpoint(account, region, "status"), &st)
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

	var drift wireDrift
	err = d.api.get(ctx, d.api.endpoint(account, region, "drift"), &drift)
	switch {
	case err == nil:
		setDrift(&data, drift)
	case driftNotYetAvailable(err):
	default:
		resp.Diagnostics.AddError("failed to read drift findings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func setUnpublished(data *EnforcementStatusDataSourceModel) {
	setStatus(data, wireStatus{State: "unpublished"})
	data.Published = types.BoolValue(false)
	data.ExpectedVersion, data.ExpectedContentHash = types.Int64Null(), types.StringNull()
}

func setStatus(data *EnforcementStatusDataSourceModel, st wireStatus) {
	data.Published = types.BoolValue(true)
	data.State = types.StringValue(st.State)
	data.ExpectedVersion = types.Int64Value(st.Expected.Version)
	data.ExpectedContentHash = types.StringValue(st.Expected.ContentHash)
	data.AppliedVersion, data.AppliedContentHash, data.AppliedAt = types.Int64Null(), types.StringNull(), types.StringNull()
	if st.Applied != nil {
		data.AppliedVersion = types.Int64Value(st.Applied.Version)
		data.AppliedContentHash = types.StringValue(st.Applied.ContentHash)
		data.AppliedAt = types.StringValue(st.Applied.AppliedAt)
	}
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
			AssetID: optionalString(n.AssetID), Group: optionalString(n.Group), Message: types.StringValue(n.Message)})
	}
}

func setDrift(data *EnforcementStatusDataSourceModel, drift wireDrift) {
	data.DriftEvaluated = types.BoolValue(!drift.ObservationStale)
	data.DriftObservedAt = optionalString(drift.ObservedAt)
	for _, f := range drift.Findings {
		data.DriftFindings = append(data.DriftFindings, driftFindingModel{
			Kind: types.StringValue(f.Kind), Severity: types.StringValue(f.Severity), Restoration: types.StringValue(f.Restoration),
			Resource: types.StringValue(f.Resource), Key: optionalString(f.Key), Detail: types.StringValue(f.Detail),
		})
	}
}

// driftNotYetAvailable is the expected answer before the first apply receipt
// or the first connector observation, not a failure.
func driftNotYetAvailable(err error) bool {
	return isAPIRefusal(err, http.StatusConflict, codeNotApplied) || isAPIRefusal(err, http.StatusNotFound, codeNotObserved)
}

func optionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

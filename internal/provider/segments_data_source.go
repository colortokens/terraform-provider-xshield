package provider

import (
	"context"
	"fmt"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &SegmentsDataSource{}
var _ datasource.DataSourceWithConfigure = &SegmentsDataSource{}

func NewSegmentsDataSource() datasource.DataSource { return &SegmentsDataSource{} }

type SegmentsDataSource struct{ client *sdk.Xshield }

type segmentSummaryModel struct {
	ID                              types.String `tfsdk:"id"`
	TagBasedPolicyName              types.String `tfsdk:"tag_based_policy_name"`
	Description                     types.String `tfsdk:"description"`
	Criteria                        types.String `tfsdk:"criteria"`
	MatchingAssets                  types.Int64  `tfsdk:"matching_assets"`
	TemplatesAssigned               types.Int64  `tfsdk:"templates_assigned"`
	NamednetworksAssigned           types.Int64  `tfsdk:"namednetworks_assigned"`
	InboundAutoSyncDeploymentMode   types.String `tfsdk:"inbound_auto_sync_deployment_mode"`
	OutboundAutoSyncDeploymentMode  types.String `tfsdk:"outbound_auto_sync_deployment_mode"`
	LowestInboundAssetPolicyStatus  types.String `tfsdk:"lowest_inbound_segment_asset_policy_status"`
	LowestOutboundAssetPolicyStatus types.String `tfsdk:"lowest_outbound_segment_asset_policy_status"`
	PolicyAutomationConfigurable    types.Bool   `tfsdk:"policy_automation_configurable"`
}

type SegmentsDataSourceModel struct {
	Criteria   types.String          `tfsdk:"criteria"`
	MaxResults types.Int64           `tfsdk:"max_results"`
	Segments   []segmentSummaryModel `tfsdk:"segments"`
	IDs        []types.String        `tfsdk:"ids"`
	Total      types.Int64           `tfsdk:"total"`
	Truncated  types.Bool            `tfsdk:"truncated"`
}

func (d *SegmentsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_segments"
}

func (d *SegmentsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Segments matching a criteria, with their membership and automation settings.\n\n" +
			"The auto-sync modes are reported in the vocabulary you write, `test`, `enforce` or `disable`, " +
			"rather than the `under-test` and `enforced` the API reads back.",
		Attributes: map[string]schema.Attribute{
			"criteria":    criteriaAttribute(false, "Criteria selecting the segments. Defaults to every segment."),
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("segments"),
			"truncated":   truncatedAttribute(),
			"ids":         idsAttribute("segments"),
			"segments": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                                 schema.StringAttribute{Computed: true},
						"tag_based_policy_name":              schema.StringAttribute{Computed: true},
						"description":                        schema.StringAttribute{Computed: true},
						"criteria":                           schema.StringAttribute{Computed: true, Description: "Criteria as stored, including the managedby clause the backend appends."},
						"matching_assets":                    schema.Int64Attribute{Computed: true, Description: "Assets currently in the segment."},
						"templates_assigned":                 schema.Int64Attribute{Computed: true},
						"namednetworks_assigned":             schema.Int64Attribute{Computed: true},
						"inbound_auto_sync_deployment_mode":  schema.StringAttribute{Computed: true, Description: "One of test, enforce or disable."},
						"outbound_auto_sync_deployment_mode": schema.StringAttribute{Computed: true, Description: "One of test, enforce or disable."},
						"lowest_inbound_segment_asset_policy_status":  schema.StringAttribute{Computed: true, Description: "Inbound policy floor applied to members."},
						"lowest_outbound_segment_asset_policy_status": schema.StringAttribute{Computed: true, Description: "Outbound policy floor applied to members."},
						"policy_automation_configurable":              schema.BoolAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *SegmentsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *SegmentsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SegmentsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.TagBasedPolicySummary, *int64, error) {
			res, err := d.client.Tagbasedpolicies.ListTagBasedPolicies(ctx, operations.ListTagBasedPoliciesRequest{
				ComputeTotal: computeTotalOn,
				SearchInput: shared.SearchInput{
					Criteria:   criteriaOrMatchAll(data.Criteria),
					Pagination: searchPagination(page, "tagbasedpolicyid"),
				},
			})
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s", res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.TagBasedPolicies == nil {
				return nil, nil, nil
			}
			return res.TagBasedPolicies.Items, paginationTotal(res.TagBasedPolicies.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list segments", err.Error())
		return
	}

	data.Segments = make([]segmentSummaryModel, 0, len(items))
	data.IDs = []types.String{}
	for _, item := range items {
		segment := segmentSummaryModel{
			ID:                              types.StringPointerValue(item.TagBasedPolicyID),
			TagBasedPolicyName:              types.StringPointerValue(item.TagBasedPolicyName),
			Description:                     types.StringPointerValue(item.Description),
			Criteria:                        types.StringPointerValue(item.Criteria),
			MatchingAssets:                  int64OrNull(item.MatchingAssets),
			TemplatesAssigned:               int64OrNull(item.TemplatesAssigned),
			NamednetworksAssigned:           int64OrNull(item.NamednetworksAssigned),
			InboundAutoSyncDeploymentMode:   normalizeAutoSyncDeploymentMode(item.InboundAutoSyncDeploymentMode),
			OutboundAutoSyncDeploymentMode:  normalizeAutoSyncDeploymentMode(item.OutboundAutoSyncDeploymentMode),
			LowestInboundAssetPolicyStatus:  types.StringPointerValue(item.LowestInboundSegmentAssetPolicyStatus),
			LowestOutboundAssetPolicyStatus: types.StringPointerValue(item.LowestOutboundSegmentAssetPolicyStatus),
			PolicyAutomationConfigurable:    types.BoolPointerValue(item.PolicyAutomationConfigurable),
		}
		data.Segments = append(data.Segments, segment)
		data.IDs = append(data.IDs, segment.ID)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

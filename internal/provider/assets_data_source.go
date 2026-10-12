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

var _ datasource.DataSource = &AssetsDataSource{}
var _ datasource.DataSourceWithConfigure = &AssetsDataSource{}

func NewAssetsDataSource() datasource.DataSource {
	return &AssetsDataSource{}
}

type AssetsDataSource struct {
	client *sdk.Xshield
}

type assetSummaryModel struct {
	ID                           types.String            `tfsdk:"id"`
	AssetName                    types.String            `tfsdk:"asset_name"`
	Type                         types.String            `tfsdk:"type"`
	CoreTags                     map[string]types.String `tfsdk:"core_tags"`
	OsName                       types.String            `tfsdk:"os_name"`
	Platform                     types.String            `tfsdk:"platform"`
	AgentStatus                  types.String            `tfsdk:"agent_status"`
	ManagedBy                    types.String            `tfsdk:"managed_by"`
	InboundAssetDeploymentState  types.String            `tfsdk:"inbound_asset_deployment_state"`
	OutboundAssetDeploymentState types.String            `tfsdk:"outbound_asset_deployment_state"`
	InboundAssetStatus           types.String            `tfsdk:"inbound_asset_status"`
	OutboundAssetStatus          types.String            `tfsdk:"outbound_asset_status"`
	InboundAssetPolicyMode       types.String            `tfsdk:"inbound_asset_policy_mode"`
	OutboundAssetPolicyMode      types.String            `tfsdk:"outbound_asset_policy_mode"`
	MicroDeploymentCompatible    types.Bool              `tfsdk:"micro_deployment_compatible"`
	PendingAttackSurfaceChanges  types.Bool              `tfsdk:"pending_attack_surface_changes"`
	PendingBlastRadiusChanges    types.Bool              `tfsdk:"pending_blast_radius_changes"`
	TotalPorts                   types.Int64             `tfsdk:"total_ports"`
	UnreviewedPorts              types.Int64             `tfsdk:"unreviewed_ports"`
}

type AssetsDataSourceModel struct {
	Criteria   types.String        `tfsdk:"criteria"`
	MaxResults types.Int64         `tfsdk:"max_results"`
	Assets     []assetSummaryModel `tfsdk:"assets"`
	IDs        []types.String      `tfsdk:"ids"`
	Total      types.Int64         `tfsdk:"total"`
	Truncated  types.Bool          `tfsdk:"truncated"`
}

func (d *AssetsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_assets"
}

func (d *AssetsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Assets matching a criteria, with the enforcement state of each.\n\n" +
			"Note that the asset search always excludes user groups and applies the caller's own access " +
			"constraint, so the criteria the server evaluates is narrower than the one sent.\n\n" +
			"`attack_surface` and `blast_radius` are risk scores rather than enforcement state; the fields " +
			"here that describe enforcement are the deployment states, the policy modes and the statuses.",
		Attributes: map[string]schema.Attribute{
			"criteria":    criteriaAttribute(true, "Criteria selecting the assets, written against the asset scope."),
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("assets"),
			"truncated":   truncatedAttribute(),
			"ids":         idsAttribute("assets"),
			"assets": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The matching assets, ordered by name with the id as a tie-break.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":         schema.StringAttribute{Computed: true, Description: "Immutable asset id."},
						"asset_name": schema.StringAttribute{Computed: true, Description: "Asset name, which is not guaranteed unique."},
						"type":       schema.StringAttribute{Computed: true, Description: "Asset type, such as server or endpoint."},
						"core_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Core tag values, the fields a segment criteria may select on.",
						},
						"os_name":                        schema.StringAttribute{Computed: true},
						"platform":                       schema.StringAttribute{Computed: true},
						"agent_status":                   schema.StringAttribute{Computed: true, Description: "Agent state. An asset with no agent cannot have policy enforced."},
						"managed_by":                     schema.StringAttribute{Computed: true, Description: "Which system manages the asset, for example colortokens or an EDR vendor."},
						"inbound_asset_deployment_state": schema.StringAttribute{Computed: true, Description: "Whether inbound enforcement is enabled or disabled."},
						"outbound_asset_deployment_state": schema.StringAttribute{
							Computed: true, Description: "Whether outbound enforcement is enabled or disabled."},
						"inbound_asset_status":        schema.StringAttribute{Computed: true, Description: "Derived inbound posture, from unsecured through to secure."},
						"outbound_asset_status":       schema.StringAttribute{Computed: true, Description: "Derived outbound posture."},
						"inbound_asset_policy_mode":   schema.StringAttribute{Computed: true, Description: "Whether inbound policy is not deployed, under test or enforced."},
						"outbound_asset_policy_mode":  schema.StringAttribute{Computed: true, Description: "Whether outbound policy is not deployed, under test or enforced."},
						"micro_deployment_compatible": schema.BoolAttribute{Computed: true, Description: "Whether the asset accepts a per-port deployment rather than only a whole-asset one."},
						"pending_attack_surface_changes": schema.BoolAttribute{
							Computed: true, Description: "True when inbound intent has changed but has not been deployed."},
						"pending_blast_radius_changes": schema.BoolAttribute{
							Computed: true, Description: "True when outbound intent has changed but has not been deployed."},
						"total_ports":      schema.Int64Attribute{Computed: true},
						"unreviewed_ports": schema.Int64Attribute{Computed: true, Description: "Listening ports with no review decision yet."},
					},
				},
			},
		},
	}
}

func (d *AssetsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *AssetsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AssetsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.ExtendedAssetSummary, *int64, error) {
			res, err := d.client.Assets.ListAssets(ctx, operations.ListAssetsRequest{
				ComputeTotal: computeTotalOn,
				SearchInput: shared.SearchInput{
					Criteria:   data.Criteria.ValueString(),
					Pagination: searchPagination(page, "assetId"),
				},
			}, operations.WithAcceptHeaderOverride(operations.AcceptHeaderEnumApplicationJson))
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s",
					res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.AssetSearchResults == nil {
				return nil, nil, nil
			}
			return res.AssetSearchResults.Items, paginationTotal(res.AssetSearchResults.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list assets", err.Error())
		return
	}

	data.Assets = make([]assetSummaryModel, 0, len(items))
	data.IDs = []types.String{}
	for _, item := range items {
		asset := assetSummaryModel{
			ID:                           types.StringPointerValue(item.AssetID),
			AssetName:                    types.StringValue(item.AssetName),
			Type:                         types.StringValue(item.Type),
			OsName:                       types.StringPointerValue(item.OsName),
			Platform:                     types.StringPointerValue(item.Platform),
			AgentStatus:                  types.StringPointerValue(item.AgentStatus),
			ManagedBy:                    types.StringPointerValue(item.ManagedBy),
			InboundAssetDeploymentState:  types.StringPointerValue(item.InboundAssetDeploymentState),
			OutboundAssetDeploymentState: types.StringPointerValue(item.OutboundAssetDeploymentState),
			InboundAssetStatus:           types.StringPointerValue(item.InboundAssetStatus),
			OutboundAssetStatus:          types.StringPointerValue(item.OutboundAssetStatus),
			InboundAssetPolicyMode:       types.StringPointerValue(item.InboundAssetPolicyMode),
			OutboundAssetPolicyMode:      types.StringPointerValue(item.OutboundAssetPolicyMode),
			MicroDeploymentCompatible:    types.BoolPointerValue(item.MicroDeploymentCompatible),
			PendingAttackSurfaceChanges:  types.BoolPointerValue(item.PendingAttackSurfaceChanges),
			PendingBlastRadiusChanges:    types.BoolPointerValue(item.PendingBlastRadiusChanges),
			TotalPorts:                   int64OrNull(item.TotalPorts),
			UnreviewedPorts:              int64OrNull(item.UnreviewedPorts),
			CoreTags:                     map[string]types.String{},
		}
		for k, v := range item.CoreTags {
			asset.CoreTags[k] = types.StringValue(v)
		}
		data.Assets = append(data.Assets, asset)
		data.IDs = append(data.IDs, asset.ID)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

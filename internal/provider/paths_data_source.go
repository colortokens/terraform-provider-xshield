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

var _ datasource.DataSource = &PathsDataSource{}
var _ datasource.DataSourceWithConfigure = &PathsDataSource{}

func NewPathsDataSource() datasource.DataSource { return &PathsDataSource{} }

type PathsDataSource struct{ client *sdk.Xshield }

type observedPathModel struct {
	ID                      types.String   `tfsdk:"id"`
	Direction               types.String   `tfsdk:"direction"`
	SourceAssetID           types.String   `tfsdk:"source_asset_id"`
	SourceAssetName         types.String   `tfsdk:"source_asset_name"`
	SourceNamedNetwork      types.String   `tfsdk:"source_named_network"`
	SrcIP                   types.String   `tfsdk:"src_ip"`
	DestinationAssetID      types.String   `tfsdk:"destination_asset_id"`
	DestinationAssetName    types.String   `tfsdk:"destination_asset_name"`
	DestinationNamedNetwork types.String   `tfsdk:"destination_named_network"`
	DstIP                   []types.String `tfsdk:"dst_ip"`
	Domain                  types.String   `tfsdk:"domain"`
	Port                    types.String   `tfsdk:"port"`
	Protocol                types.String   `tfsdk:"protocol"`
	Reviewed                types.String   `tfsdk:"reviewed"`
	Enforced                types.String   `tfsdk:"enforced"`
	InternetFacing          types.Bool     `tfsdk:"internet_facing"`
	MatchedByTemplates      []types.String `tfsdk:"matched_by_templates"`
	ConnectionCount         types.Int64    `tfsdk:"connection_count"`
}

type PathsDataSourceModel struct {
	Criteria            types.String        `tfsdk:"criteria"`
	SourceCriteria      types.String        `tfsdk:"source_criteria"`
	DestinationCriteria types.String        `tfsdk:"destination_criteria"`
	MaxResults          types.Int64         `tfsdk:"max_results"`
	Paths               []observedPathModel `tfsdk:"paths"`
	Total               types.Int64         `tfsdk:"total"`
	Truncated           types.Bool          `tfsdk:"truncated"`
}

func (d *PathsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_paths"
}

func (d *PathsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Traffic paths observed between assets and their peers.\n\n" +
			"Use this to see which peers actually talk to an asset before deciding which template paths to " +
			"write. As with ports, `reviewed` is the intent and `enforced` is what the firewall runs.",
		Attributes: map[string]schema.Attribute{
			"criteria": criteriaAttribute(true, "Criteria selecting the paths, written against the path scope."),
			"source_criteria": schema.StringAttribute{
				Optional:    true,
				Description: "Additional criteria narrowing the source side of the path.",
			},
			"destination_criteria": schema.StringAttribute{
				Optional:    true,
				Description: "Additional criteria narrowing the destination side of the path.",
			},
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("paths"),
			"truncated":   truncatedAttribute(),
			"paths": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                        schema.StringAttribute{Computed: true, Description: "Channel hash identifying the path."},
						"direction":                 schema.StringAttribute{Computed: true, Description: "Inbound or outbound, relative to the asset."},
						"source_asset_id":           schema.StringAttribute{Computed: true},
						"source_asset_name":         schema.StringAttribute{Computed: true},
						"source_named_network":      schema.StringAttribute{Computed: true, Description: "Named network the source falls in, when it is not a managed asset."},
						"src_ip":                    schema.StringAttribute{Computed: true},
						"destination_asset_id":      schema.StringAttribute{Computed: true},
						"destination_asset_name":    schema.StringAttribute{Computed: true},
						"destination_named_network": schema.StringAttribute{Computed: true, Description: "Named network the destination falls in."},
						"dst_ip":                    schema.ListAttribute{Computed: true, ElementType: types.StringType},
						"domain":                    schema.StringAttribute{Computed: true},
						"port":                      schema.StringAttribute{Computed: true},
						"protocol":                  schema.StringAttribute{Computed: true},
						"reviewed":                  schema.StringAttribute{Computed: true, Description: "The decision recorded for this path."},
						"enforced":                  schema.StringAttribute{Computed: true, Description: "What the firewall is enforcing for this path today."},
						"internet_facing":           schema.BoolAttribute{Computed: true},
						"matched_by_templates":      schema.ListAttribute{Computed: true, ElementType: types.StringType},
						"connection_count":          schema.Int64Attribute{Computed: true, Description: "Connections observed over the reporting window."},
					},
				},
			},
		},
	}
}

func (d *PathsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *PathsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PathsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.Path, *int64, error) {
			search := shared.PathSearchInput{
				Criteria:   data.Criteria.ValueString(),
				Pagination: searchPagination(page, "channelhash"),
			}
			if !data.SourceCriteria.IsNull() && data.SourceCriteria.ValueString() != "" {
				search.SourceCriteria = data.SourceCriteria.ValueStringPointer()
			}
			if !data.DestinationCriteria.IsNull() && data.DestinationCriteria.ValueString() != "" {
				search.DestinationCriteria = data.DestinationCriteria.ValueStringPointer()
			}
			res, err := d.client.Paths.ListPaths(ctx, operations.ListPathsRequest{
				ComputeTotal:    computeTotalOn,
				PathSearchInput: search,
			})
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s", res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.Paths == nil {
				return nil, nil, nil
			}
			return res.Paths.Items, paginationTotal(res.Paths.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list paths", err.Error())
		return
	}

	data.Paths = make([]observedPathModel, 0, len(items))
	for _, item := range items {
		p := observedPathModel{
			ID:                      types.StringPointerValue(item.ChannelHash),
			Direction:               types.StringPointerValue(item.Direction),
			SrcIP:                   types.StringPointerValue(item.SrcIP),
			DstIP:                   stringList(item.DstIP),
			Domain:                  types.StringPointerValue(item.Domain),
			Port:                    types.StringPointerValue(item.Port),
			Protocol:                types.StringPointerValue(item.Protocol),
			Reviewed:                types.StringPointerValue(item.Reviewed),
			Enforced:                types.StringPointerValue(item.Enforced),
			InternetFacing:          types.BoolPointerValue(item.InternetFacing),
			ConnectionCount:         int64OrNull(item.ConnectionCount),
			MatchedByTemplates:      []types.String{},
			SourceAssetID:           types.StringNull(),
			SourceAssetName:         types.StringNull(),
			SourceNamedNetwork:      types.StringNull(),
			DestinationAssetID:      types.StringNull(),
			DestinationAssetName:    types.StringNull(),
			DestinationNamedNetwork: types.StringNull(),
		}
		if item.SourceAsset != nil {
			p.SourceAssetID = types.StringPointerValue(item.SourceAsset.AssetID)
			p.SourceAssetName = types.StringValue(item.SourceAsset.AssetName)
		}
		if item.DestinationAsset != nil {
			p.DestinationAssetID = types.StringPointerValue(item.DestinationAsset.AssetID)
			p.DestinationAssetName = types.StringValue(item.DestinationAsset.AssetName)
		}
		if item.SourceNamedNetwork != nil {
			p.SourceNamedNetwork = types.StringPointerValue(item.SourceNamedNetwork.NamedNetworkName)
		}
		if item.DestinationNamedNetwork != nil {
			p.DestinationNamedNetwork = types.StringPointerValue(item.DestinationNamedNetwork.NamedNetworkName)
		}
		for _, t := range item.MatchedByTemplates {
			p.MatchedByTemplates = append(p.MatchedByTemplates, types.StringPointerValue(t.TemplateName))
		}
		data.Paths = append(data.Paths, p)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

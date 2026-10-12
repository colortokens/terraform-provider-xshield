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

var _ datasource.DataSource = &NamedNetworksDataSource{}
var _ datasource.DataSourceWithConfigure = &NamedNetworksDataSource{}

func NewNamedNetworksDataSource() datasource.DataSource { return &NamedNetworksDataSource{} }

type NamedNetworksDataSource struct{ client *sdk.Xshield }

type namedNetworkRangeModel struct {
	IPRange types.String `tfsdk:"ip_range"`
	IPCount types.Int64  `tfsdk:"ip_count"`
}

type namedNetworkSummaryModel struct {
	ID                       types.String             `tfsdk:"id"`
	NamedNetworkName         types.String             `tfsdk:"named_network_name"`
	NamedNetworkDescription  types.String             `tfsdk:"named_network_description"`
	IPRanges                 []namedNetworkRangeModel `tfsdk:"ip_ranges"`
	TotalCount               types.Int64              `tfsdk:"total_count"`
	AssetAssignments         types.Int64              `tfsdk:"asset_assignments"`
	SegmentAssignments       types.Int64              `tfsdk:"segment_assignments"`
	ProgramAsIntranet        types.Bool               `tfsdk:"program_as_intranet"`
	ProgramAsInternet        types.Bool               `tfsdk:"program_as_internet"`
	ColortokensManaged       types.Bool               `tfsdk:"colortokens_managed"`
	AssignedByTagBasedPolicy types.Bool               `tfsdk:"assigned_by_tag_based_policy"`
	Region                   types.String             `tfsdk:"region"`
	Service                  types.String             `tfsdk:"service"`
}

type NamedNetworksDataSourceModel struct {
	Criteria      types.String               `tfsdk:"criteria"`
	MaxResults    types.Int64                `tfsdk:"max_results"`
	NamedNetworks []namedNetworkSummaryModel `tfsdk:"named_networks"`
	IDs           []types.String             `tfsdk:"ids"`
	Total         types.Int64                `tfsdk:"total"`
	Truncated     types.Bool                 `tfsdk:"truncated"`
}

func (d *NamedNetworksDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_named_networks"
}

func (d *NamedNetworksDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Named networks matching a criteria, with their address ranges.\n\n" +
			"Ranges are reported in the canonical form the backend stores, which may differ from the text " +
			"originally entered.",
		Attributes: map[string]schema.Attribute{
			"criteria":    criteriaAttribute(false, "Criteria selecting the named networks. Defaults to every named network."),
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("named networks"),
			"truncated":   truncatedAttribute(),
			"ids":         idsAttribute("named networks"),
			"named_networks": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                        schema.StringAttribute{Computed: true},
						"named_network_name":        schema.StringAttribute{Computed: true},
						"named_network_description": schema.StringAttribute{Computed: true},
						"ip_ranges": schema.ListNestedAttribute{
							Computed: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"ip_range": schema.StringAttribute{Computed: true, Description: "Range in canonical CIDR form."},
									"ip_count": schema.Int64Attribute{Computed: true, Description: "Addresses the range covers."},
								},
							},
						},
						"total_count":                  schema.Int64Attribute{Computed: true, Description: "Total addresses across every range."},
						"asset_assignments":            schema.Int64Attribute{Computed: true},
						"segment_assignments":          schema.Int64Attribute{Computed: true},
						"program_as_intranet":          schema.BoolAttribute{Computed: true, Description: "Whether traffic to this network counts as intranet."},
						"program_as_internet":          schema.BoolAttribute{Computed: true, Description: "Whether traffic to this network counts as internet."},
						"colortokens_managed":          schema.BoolAttribute{Computed: true, Description: "True for a network shipped with the platform."},
						"assigned_by_tag_based_policy": schema.BoolAttribute{Computed: true},
						"region":                       schema.StringAttribute{Computed: true},
						"service":                      schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *NamedNetworksDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *NamedNetworksDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data NamedNetworksDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.NamednetworkNamedNetwork, *int64, error) {
			res, err := d.client.Namednetworks.ListNamedNetworks(ctx, operations.ListNamedNetworksRequest{
				ComputeTotal: computeTotalOn,
				SearchInput: shared.SearchInput{
					Criteria:   criteriaOrMatchAll(data.Criteria),
					Pagination: searchPagination(page, "namednetworkid"),
				},
			})
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s", res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.NamedNetworks == nil {
				return nil, nil, nil
			}
			return res.NamedNetworks.Items, paginationTotal(res.NamedNetworks.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list named networks", err.Error())
		return
	}

	data.NamedNetworks = make([]namedNetworkSummaryModel, 0, len(items))
	data.IDs = []types.String{}
	for _, item := range items {
		network := namedNetworkSummaryModel{
			ID:                       types.StringPointerValue(item.ID),
			NamedNetworkName:         types.StringPointerValue(item.NamedNetworkName),
			NamedNetworkDescription:  types.StringPointerValue(item.NamedNetworkDescription),
			TotalCount:               int64OrNull(item.TotalCount),
			AssetAssignments:         int64OrNull(item.NamedNetworkAssignments),
			SegmentAssignments:       int64OrNull(item.NamednetworkTagBasedPolicyAssignments),
			ProgramAsIntranet:        types.BoolPointerValue(item.ProgramAsIntranet),
			ProgramAsInternet:        types.BoolPointerValue(item.ProgramAsInternet),
			ColortokensManaged:       types.BoolPointerValue(item.ColortokensManaged),
			AssignedByTagBasedPolicy: types.BoolPointerValue(item.AssignedByTagBasedPolicy),
			Region:                   types.StringPointerValue(item.Region),
			Service:                  types.StringPointerValue(item.Service),
			IPRanges:                 []namedNetworkRangeModel{},
		}
		for _, r := range item.IPRanges {
			network.IPRanges = append(network.IPRanges, namedNetworkRangeModel{
				IPRange: types.StringPointerValue(r.IPRange),
				IPCount: int64OrNull(r.IPCount),
			})
		}
		data.NamedNetworks = append(data.NamedNetworks, network)
		data.IDs = append(data.IDs, network.ID)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

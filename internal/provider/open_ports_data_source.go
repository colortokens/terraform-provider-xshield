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

var _ datasource.DataSource = &OpenPortsDataSource{}
var _ datasource.DataSourceWithConfigure = &OpenPortsDataSource{}

func NewOpenPortsDataSource() datasource.DataSource { return &OpenPortsDataSource{} }

type OpenPortsDataSource struct{ client *sdk.Xshield }

type openPortModel struct {
	ID                 types.String   `tfsdk:"id"`
	AssetID            types.String   `tfsdk:"asset_id"`
	AssetName          types.String   `tfsdk:"asset_name"`
	ListenPort         types.String   `tfsdk:"listen_port"`
	ListenPortProtocol types.String   `tfsdk:"listen_port_protocol"`
	ListenPortName     types.String   `tfsdk:"listen_port_name"`
	ListenPortReviewed types.String   `tfsdk:"listen_port_reviewed"`
	ListenPortEnforced types.String   `tfsdk:"listen_port_enforced"`
	ListenProcessNames []types.String `tfsdk:"listen_process_names"`
	MatchedByTemplates []types.String `tfsdk:"matched_by_templates"`
	PathCount          types.Int64    `tfsdk:"path_count"`
	InternetPathCount  types.Int64    `tfsdk:"internet_path_count"`
	PublicInterface    types.Bool     `tfsdk:"listening_on_public_interface"`
}

type OpenPortsDataSourceModel struct {
	Criteria            types.String    `tfsdk:"criteria"`
	SourceCriteria      types.String    `tfsdk:"source_criteria"`
	DestinationCriteria types.String    `tfsdk:"destination_criteria"`
	MaxResults          types.Int64     `tfsdk:"max_results"`
	Ports               []openPortModel `tfsdk:"ports"`
	Total               types.Int64     `tfsdk:"total"`
	Truncated           types.Bool      `tfsdk:"truncated"`
}

func (d *OpenPortsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_open_ports"
}

func (d *OpenPortsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Listening ports observed on assets, with the review decision and what is enforced.\n\n" +
			"This is how to see what a template would have to cover before writing one. Each port carries two " +
			"states: `listen_port_reviewed` is the intent, `listen_port_enforced` is what the firewall is " +
			"actually running. They differ until a deployment runs.\n\n" +
			"The two scales are not the same enum. A template port takes `denied`, `allow-intranet`, " +
			"`allow-any`, `path-restricted` or `on-demand`, whereas the enforced value here can also be " +
			"`allowed-by-assetpolicy` or `allowed-test-denied`.",
		Attributes: map[string]schema.Attribute{
			"criteria": criteriaAttribute(true, "Criteria selecting the ports, written against the port scope."),
			"source_criteria": schema.StringAttribute{
				Optional:    true,
				Description: "Additional criteria narrowing the peer at the far end of the observed traffic.",
			},
			"destination_criteria": schema.StringAttribute{
				Optional:    true,
				Description: "Additional criteria narrowing the destination of the observed traffic.",
			},
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("ports"),
			"truncated":   truncatedAttribute(),
			"ports": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                   schema.StringAttribute{Computed: true, Description: "Port identifier, derived from the port, protocol and direction."},
						"asset_id":             schema.StringAttribute{Computed: true},
						"asset_name":           schema.StringAttribute{Computed: true},
						"listen_port":          schema.StringAttribute{Computed: true, Description: "Port number, or a range such as 8000-8100."},
						"listen_port_protocol": schema.StringAttribute{Computed: true},
						"listen_port_name":     schema.StringAttribute{Computed: true},
						"listen_port_reviewed": schema.StringAttribute{Computed: true, Description: "The decision recorded for this port, which is intent rather than enforcement."},
						"listen_port_enforced": schema.StringAttribute{Computed: true, Description: "What the firewall is enforcing for this port today."},
						"listen_process_names": schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "Processes observed listening on the port."},
						"matched_by_templates": schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "Names of the templates whose rules cover this port."},
						"path_count":           schema.Int64Attribute{Computed: true, Description: "Observed traffic paths reaching this port."},
						"internet_path_count":  schema.Int64Attribute{Computed: true, Description: "How many of those paths came from the internet."},
						"listening_on_public_interface": schema.BoolAttribute{
							Computed: true, Description: "True when the port is bound to a publicly reachable interface."},
					},
				},
			},
		},
	}
}

func (d *OpenPortsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *OpenPortsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data OpenPortsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.OpenPort, *int64, error) {
			search := shared.PathSearchInput{
				Criteria:   data.Criteria.ValueString(),
				Pagination: searchPagination(page, "lpid"),
			}
			if !data.SourceCriteria.IsNull() && data.SourceCriteria.ValueString() != "" {
				search.SourceCriteria = data.SourceCriteria.ValueStringPointer()
			}
			if !data.DestinationCriteria.IsNull() && data.DestinationCriteria.ValueString() != "" {
				search.DestinationCriteria = data.DestinationCriteria.ValueStringPointer()
			}
			res, err := d.client.Openports.ListPorts(ctx, operations.ListPortsRequest{
				ComputeTotal:    computeTotalOn,
				PathSearchInput: search,
			})
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s", res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.OpenPorts == nil {
				return nil, nil, nil
			}
			return res.OpenPorts.Items, paginationTotal(res.OpenPorts.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list open ports", err.Error())
		return
	}

	data.Ports = make([]openPortModel, 0, len(items))
	for _, item := range items {
		port := openPortModel{
			ID:                 types.StringPointerValue(item.LpID),
			ListenPort:         types.StringPointerValue(item.ListenPort),
			ListenPortProtocol: types.StringPointerValue(item.ListenPortProtocol),
			ListenPortName:     types.StringPointerValue(item.ListenPortName),
			ListenPortReviewed: types.StringPointerValue(item.ListenPortReviewed),
			ListenPortEnforced: types.StringPointerValue(item.ListenPortEnforced),
			ListenProcessNames: stringList(item.ListenProcessNames),
			PathCount:          int64OrNull(item.PathCount),
			InternetPathCount:  int64OrNull(item.InternetPathCount),
			PublicInterface:    types.BoolPointerValue(item.Listeningonpublicinterface),
			MatchedByTemplates: []types.String{},
			AssetID:            types.StringNull(),
			AssetName:          types.StringNull(),
		}
		if item.ListenAsset != nil {
			port.AssetID = types.StringPointerValue(item.ListenAsset.AssetID)
			port.AssetName = types.StringValue(item.ListenAsset.AssetName)
		}
		for _, t := range item.MatchedByTemplates {
			port.MatchedByTemplates = append(port.MatchedByTemplates, types.StringPointerValue(t.TemplateName))
		}
		data.Ports = append(data.Ports, port)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

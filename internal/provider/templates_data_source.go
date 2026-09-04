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

var _ datasource.DataSource = &TemplatesDataSource{}
var _ datasource.DataSourceWithConfigure = &TemplatesDataSource{}

func NewTemplatesDataSource() datasource.DataSource { return &TemplatesDataSource{} }

type TemplatesDataSource struct{ client *sdk.Xshield }

type templateSummaryModel struct {
	ID                       types.String `tfsdk:"id"`
	TemplateName             types.String `tfsdk:"template_name"`
	TemplateDescription      types.String `tfsdk:"template_description"`
	TemplateCategory         types.String `tfsdk:"template_category"`
	TemplateType             types.String `tfsdk:"template_type"`
	PortCount                types.Int64  `tfsdk:"port_count"`
	PathCount                types.Int64  `tfsdk:"path_count"`
	AssetAssignments         types.Int64  `tfsdk:"asset_assignments"`
	SegmentAssignments       types.Int64  `tfsdk:"segment_assignments"`
	ColortokensManaged       types.Bool   `tfsdk:"colortokens_managed"`
	AccessPolicyTemplate     types.Bool   `tfsdk:"access_policy_template"`
	AssignedByTagBasedPolicy types.Bool   `tfsdk:"assigned_by_tag_based_policy"`
}

type TemplatesDataSourceModel struct {
	Criteria   types.String           `tfsdk:"criteria"`
	MaxResults types.Int64            `tfsdk:"max_results"`
	Templates  []templateSummaryModel `tfsdk:"templates"`
	IDs        []types.String         `tfsdk:"ids"`
	Total      types.Int64            `tfsdk:"total"`
	Truncated  types.Bool             `tfsdk:"truncated"`
}

func (d *TemplatesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_templates"
}

func (d *TemplatesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Templates matching a criteria, with how widely each is assigned.\n\n" +
			"Only two template types exist, `application-template` and `block-template`. Rule counts are " +
			"reported here; read a single template through `xshield_template` for its ports and paths.",
		Attributes: map[string]schema.Attribute{
			"criteria":    criteriaAttribute(false, "Criteria selecting the templates. Defaults to every template."),
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("templates"),
			"truncated":   truncatedAttribute(),
			"ids":         idsAttribute("templates"),
			"templates": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                           schema.StringAttribute{Computed: true},
						"template_name":                schema.StringAttribute{Computed: true},
						"template_description":         schema.StringAttribute{Computed: true},
						"template_category":            schema.StringAttribute{Computed: true},
						"template_type":                schema.StringAttribute{Computed: true, Description: "Either application-template or block-template."},
						"port_count":                   schema.Int64Attribute{Computed: true, Description: "Number of port rules in the template."},
						"path_count":                   schema.Int64Attribute{Computed: true, Description: "Number of path rules in the template."},
						"asset_assignments":            schema.Int64Attribute{Computed: true, Description: "Assets the template is applied to."},
						"segment_assignments":          schema.Int64Attribute{Computed: true, Description: "Segments the template is attached to."},
						"colortokens_managed":          schema.BoolAttribute{Computed: true, Description: "True for a template shipped with the platform, which cannot be edited."},
						"access_policy_template":       schema.BoolAttribute{Computed: true},
						"assigned_by_tag_based_policy": schema.BoolAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *TemplatesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *TemplatesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TemplatesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.TemplateSummary, *int64, error) {
			res, err := d.client.Templates.ListTemplates(ctx, operations.ListTemplatesRequest{
				ComputeTotal: computeTotalOn,
				SearchInput: shared.SearchInput{
					Criteria:   criteriaOrMatchAll(data.Criteria),
					Pagination: searchPagination(page, "templateid"),
				},
			})
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s", res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.Templates == nil {
				return nil, nil, nil
			}
			return res.Templates.Items, paginationTotal(res.Templates.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list templates", err.Error())
		return
	}

	data.Templates = make([]templateSummaryModel, 0, len(items))
	data.IDs = []types.String{}
	for _, item := range items {
		template := templateSummaryModel{
			ID:                       types.StringPointerValue(item.TemplateID),
			TemplateName:             types.StringPointerValue(item.TemplateName),
			TemplateDescription:      types.StringPointerValue(item.TemplateDescription),
			TemplateCategory:         types.StringPointerValue(item.TemplateCategory),
			TemplateType:             types.StringValue(item.TemplateType),
			PortCount:                int64OrNull(item.TemplatePorts),
			PathCount:                int64OrNull(item.TemplatePaths),
			AssetAssignments:         int64OrNull(item.TemplateAssignments),
			SegmentAssignments:       int64OrNull(item.TemplateTagBasedPolicyAssignments),
			ColortokensManaged:       types.BoolPointerValue(item.OobTemplate),
			AccessPolicyTemplate:     types.BoolPointerValue(item.AccessPolicyTemplate),
			AssignedByTagBasedPolicy: types.BoolPointerValue(item.AssignedByTagBasedPolicy),
		}
		data.Templates = append(data.Templates, template)
		data.IDs = append(data.IDs, template.ID)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

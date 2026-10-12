package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &FieldValuesDataSource{}
var _ datasource.DataSourceWithConfigure = &FieldValuesDataSource{}

func NewFieldValuesDataSource() datasource.DataSource {
	return &FieldValuesDataSource{}
}

type FieldValuesDataSource struct {
	client *sdk.Xshield
}

type FieldValuesDataSourceModel struct {
	Field    types.String           `tfsdk:"field"`
	Criteria types.String           `tfsdk:"criteria"`
	Scope    types.String           `tfsdk:"scope"`
	Contains types.String           `tfsdk:"contains"`
	Values   map[string]types.Int64 `tfsdk:"values"`
	Names    []types.String         `tfsdk:"names"`
	HasMore  types.Bool             `tfsdk:"has_more"`
}

func (d *FieldValuesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_field_values"
}

func (d *FieldValuesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The distinct values of one field, with the number of objects carrying each.\n\n" +
			"This answers \"what values does this tag actually take in my tenant\", which is the question a " +
			"criteria depends on. The field must be facetable; `xshield_fields` reports which are.",
		Attributes: map[string]schema.Attribute{
			"field": schema.StringAttribute{
				Required:    true,
				Description: "Internal name of the field to summarise, for example `environment`.",
			},
			"criteria": criteriaAttribute(false,
				"Narrow the population before counting. Defaults to every object in the scope."),
			"scope": schema.StringAttribute{
				Optional:    true,
				Description: "Scope the field belongs to, for example `asset`. Defaults to the asset scope.",
			},
			"contains": schema.StringAttribute{
				Optional:    true,
				Description: "Return only values containing this text, matched case-insensitively.",
			},
			"values": schema.MapAttribute{
				Computed:    true,
				ElementType: types.Int64Type,
				Description: "Each value and the number of objects carrying it.",
			},
			"names": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "The values alone, sorted, for use in a `for_each` or an `in` clause.",
			},
			"has_more": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the field has more distinct values than the API returned in one summary.",
			},
		},
	}
}

func (d *FieldValuesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *FieldValuesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data FieldValuesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := shared.SummarizeField{
		Criteria:   criteriaOrMatchAll(data.Criteria),
		FacetField: data.Field.ValueString(),
	}
	if !data.Scope.IsNull() && data.Scope.ValueString() != "" {
		request.Scope = data.Scope.ValueStringPointer()
	}
	if !data.Contains.IsNull() && data.Contains.ValueString() != "" {
		request.FacetFieldFilter = data.Contains.ValueStringPointer()
	}

	res, err := d.client.Metadata.SummarizeField(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Cannot summarise %q", data.Field.ValueString()), err.Error())
		return
	}
	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Cannot summarise %q: the API answered %d", data.Field.ValueString(), res.StatusCode),
			apiErrorDetail(res.ErrorResponse, res.RawResponse))
		return
	}

	data.Values = map[string]types.Int64{}
	data.Names = []types.String{}
	data.HasMore = types.BoolValue(false)

	if res.SummarizeFieldResults != nil && res.SummarizeFieldResults.Facet != nil {
		facet := res.SummarizeFieldResults.Facet
		names := make([]string, 0, len(facet.Values))
		for name, count := range facet.Values {
			names = append(names, name)
			data.Values[name] = types.Int64Value(count)
		}
		sort.Strings(names)
		data.Names = stringList(names)
		if facet.HasMore != nil {
			data.HasMore = types.BoolValue(*facet.HasMore)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

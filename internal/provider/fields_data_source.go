package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &FieldsDataSource{}
var _ datasource.DataSourceWithConfigure = &FieldsDataSource{}

func NewFieldsDataSource() datasource.DataSource {
	return &FieldsDataSource{}
}

type FieldsDataSource struct {
	client *sdk.Xshield
}

type fieldValueModel struct {
	Display  types.String   `tfsdk:"display"`
	Internal types.Int64    `tfsdk:"internal"`
	Synonyms []types.String `tfsdk:"synonyms"`
}

type fieldModel struct {
	InternalName types.String      `tfsdk:"internal_name"`
	DisplayName  types.String      `tfsdk:"display_name"`
	Qualifier    types.String      `tfsdk:"qualifier"`
	DataType     types.String      `tfsdk:"data_type"`
	Unit         types.String      `tfsdk:"unit"`
	CoreTag      types.Bool        `tfsdk:"core_tag"`
	UserDefined  types.Bool        `tfsdk:"user_defined"`
	Multivalued  types.Bool        `tfsdk:"multivalued"`
	Sortable     types.Bool        `tfsdk:"sortable"`
	Facetable    types.Bool        `tfsdk:"facetable"`
	Searchable   types.Bool        `tfsdk:"searchable"`
	ListOfValues types.Bool        `tfsdk:"list_of_values"`
	Values       []fieldValueModel `tfsdk:"values"`
}

type FieldsDataSourceModel struct {
	Scope         types.String   `tfsdk:"scope"`
	Fields        []fieldModel   `tfsdk:"fields"`
	CoreTagNames  []types.String `tfsdk:"core_tag_names"`
	SortableNames []types.String `tfsdk:"sortable_names"`
}

func (d *FieldsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fields"
}

func (d *FieldsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The searchable fields for a scope, which is the catalogue a criteria is written against.\n\n" +
			"Use this to discover which tag keys exist, which of them are core tags usable in a segment criteria, " +
			"and the closed set of values an enumerated field accepts. This is the field catalogue, not the legacy " +
			"custom tag list at `/api/tags`.",
		Attributes: map[string]schema.Attribute{
			"scope": schema.StringAttribute{
				Optional: true,
				Description: "Limit the catalogue to one scope, for example `asset`, `path`, `port`, `template`, " +
					"`namednetwork`, `tagrule` or `tagbasedpolicy`. Left unset, every field is returned. " +
					"An unknown scope is rejected by the API.",
			},
			"core_tag_names": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Internal names of the core tag fields, sorted. These are the fields a segment criteria may use.",
			},
			"sortable_names": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Internal names of the fields that may appear in a sort, sorted.",
			},
			"fields": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Every field in the scope, ordered by internal name.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"internal_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name to use in a criteria. Field names are matched case-insensitively.",
						},
						"display_name": schema.StringAttribute{
							Computed:    true,
							Description: "Human readable name, which a criteria may also use when quoted.",
						},
						"qualifier":      schema.StringAttribute{Computed: true, Description: "Scope the field belongs to."},
						"data_type":      schema.StringAttribute{Computed: true, Description: "Value type, which decides how a literal is validated."},
						"unit":           schema.StringAttribute{Computed: true, Description: "Unit for a numeric or timestamp field, such as the age unit for a relative time."},
						"core_tag":       schema.BoolAttribute{Computed: true, Description: "True when the field is a core tag, the only kind a segment criteria may use."},
						"user_defined":   schema.BoolAttribute{Computed: true, Description: "True when the field was added for this tenant rather than shipped with the platform."},
						"multivalued":    schema.BoolAttribute{Computed: true, Description: "True when the field holds several values, which cannot be compared with the ordering operators."},
						"sortable":       schema.BoolAttribute{Computed: true, Description: "True when the field may be used in a sort."},
						"facetable":      schema.BoolAttribute{Computed: true, Description: "True when the field may be summarised, which `xshield_field_values` requires."},
						"searchable":     schema.BoolAttribute{Computed: true, Description: "True when the field may appear in a criteria."},
						"list_of_values": schema.BoolAttribute{Computed: true, Description: "True when the field accepts only the values listed below."},
						"values": schema.ListNestedAttribute{
							Computed:    true,
							Description: "The closed value set, present only for a list-of-values field. Use `display` in a criteria.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"display":  schema.StringAttribute{Computed: true, Description: "Value as written in a criteria."},
									"internal": schema.Int64Attribute{Computed: true, Description: "Value as stored."},
									"synonyms": schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "Alternative spellings the API also accepts."},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *FieldsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *FieldsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data FieldsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := operations.ListFieldsRequest{}
	if !data.Scope.IsNull() && data.Scope.ValueString() != "" {
		request.Scope = data.Scope.ValueStringPointer()
	}

	res, err := d.client.Metadata.ListFields(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Cannot list fields", err.Error())
		return
	}
	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Cannot list fields: the API answered %d", res.StatusCode),
			apiErrorDetail(res.ErrorResponse, res.RawResponse))
		return
	}
	if res.MetadataResponse == nil {
		resp.Diagnostics.AddError("Cannot list fields", "the API returned no field catalogue")
		return
	}

	names := make([]string, 0, len(res.MetadataResponse.Columns))
	for name := range res.MetadataResponse.Columns {
		names = append(names, name)
	}
	sort.Strings(names)

	data.Fields = make([]fieldModel, 0, len(names))
	data.CoreTagNames = []types.String{}
	data.SortableNames = []types.String{}
	for _, name := range names {
		column := res.MetadataResponse.Columns[name]
		field := fieldModel{
			InternalName: types.StringValue(name),
			DisplayName:  types.StringPointerValue(column.DisplayName),
			Qualifier:    types.StringPointerValue(column.Qualifier),
			Unit:         types.StringPointerValue(column.Unit),
			CoreTag:      types.BoolPointerValue(column.CoreTag),
			UserDefined:  types.BoolPointerValue(column.UserDefined),
			Multivalued:  types.BoolPointerValue(column.Multivalued),
			Sortable:     types.BoolPointerValue(column.Sortable),
			Facetable:    types.BoolPointerValue(column.Facetable),
			Searchable:   types.BoolPointerValue(column.Searchable),
			ListOfValues: types.BoolPointerValue(column.ListOfValues),
			Values:       []fieldValueModel{},
		}
		if column.DataType != nil {
			field.DataType = types.StringValue(string(*column.DataType))
		} else {
			field.DataType = types.StringNull()
		}
		for _, v := range column.Values {
			field.Values = append(field.Values, fieldValueModel{
				Display:  types.StringPointerValue(v.Display),
				Internal: types.Int64PointerValue(v.Internal),
				Synonyms: stringList(v.Synonyms),
			})
		}
		data.Fields = append(data.Fields, field)

		if column.CoreTag != nil && *column.CoreTag {
			data.CoreTagNames = append(data.CoreTagNames, types.StringValue(name))
		}
		if column.Sortable != nil && *column.Sortable {
			data.SortableNames = append(data.SortableNames, types.StringValue(name))
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

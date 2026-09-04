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

var _ datasource.DataSource = &TagRulesDataSource{}
var _ datasource.DataSourceWithConfigure = &TagRulesDataSource{}

func NewTagRulesDataSource() datasource.DataSource { return &TagRulesDataSource{} }

type TagRulesDataSource struct{ client *sdk.Xshield }

type tagRuleSummaryModel struct {
	ID              types.String            `tfsdk:"id"`
	RuleName        types.String            `tfsdk:"rule_name"`
	RuleDescription types.String            `tfsdk:"rule_description"`
	RuleCriteria    types.String            `tfsdk:"rule_criteria"`
	RuleEnabled     types.Bool              `tfsdk:"rule_enabled"`
	OnMatch         map[string]types.String `tfsdk:"on_match"`
	MatchingAssets  types.Int64             `tfsdk:"matching_assets"`
}

type TagRulesDataSourceModel struct {
	Criteria   types.String          `tfsdk:"criteria"`
	MaxResults types.Int64           `tfsdk:"max_results"`
	TagRules   []tagRuleSummaryModel `tfsdk:"tag_rules"`
	IDs        []types.String        `tfsdk:"ids"`
	Total      types.Int64           `tfsdk:"total"`
	Truncated  types.Bool            `tfsdk:"truncated"`
}

func (d *TagRulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tag_rules"
}

func (d *TagRulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Tag rules matching a criteria, with the tags each applies.\n\n" +
			"Tag rules decide the core tag values that segment criteria then select on, so this is where to " +
			"look when a segment matches fewer assets than expected. Unlike a segment criteria, a rule " +
			"criteria is stored exactly as written.",
		Attributes: map[string]schema.Attribute{
			"criteria":    criteriaAttribute(false, "Criteria selecting the tag rules. Defaults to every tag rule."),
			"max_results": maxResultsAttribute(),
			"total":       totalAttribute("tag rules"),
			"truncated":   truncatedAttribute(),
			"ids":         idsAttribute("tag rules"),
			"tag_rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":               schema.StringAttribute{Computed: true},
						"rule_name":        schema.StringAttribute{Computed: true},
						"rule_description": schema.StringAttribute{Computed: true},
						"rule_criteria":    schema.StringAttribute{Computed: true, Description: "Criteria deciding which assets the rule tags."},
						"rule_enabled":     schema.BoolAttribute{Computed: true, Description: "A disabled rule is not evaluated."},
						"on_match": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Tags applied to a matching asset.",
						},
						"matching_assets": schema.Int64Attribute{Computed: true, Description: "Assets the rule currently matches."},
					},
				},
			},
		},
	}
}

func (d *TagRulesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *TagRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TagRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	items, total, truncated, err := collectPages(ctx, data.MaxResults.ValueInt64(),
		func(ctx context.Context, page pageRequest) ([]shared.TagRule, *int64, error) {
			res, err := d.client.Tagrules.ListTagRules(ctx, operations.ListTagRulesRequest{
				ComputeTotal: computeTotalOn,
				SearchInput: shared.SearchInput{
					Criteria:   criteriaOrMatchAll(data.Criteria),
					Pagination: searchPagination(page, "ruleid"),
				},
			})
			if err != nil {
				return nil, nil, err
			}
			if res.StatusCode != 200 {
				return nil, nil, fmt.Errorf("the API answered %d: %s", res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
			}
			if res.TagRules == nil {
				return nil, nil, nil
			}
			return res.TagRules.Items, paginationTotal(res.TagRules.Metadata), nil
		})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list tag rules", err.Error())
		return
	}

	data.TagRules = make([]tagRuleSummaryModel, 0, len(items))
	data.IDs = []types.String{}
	for _, item := range items {
		rule := tagRuleSummaryModel{
			ID:              types.StringPointerValue(item.ID),
			RuleName:        types.StringPointerValue(item.RuleName),
			RuleDescription: types.StringPointerValue(item.RuleDescription),
			RuleCriteria:    types.StringValue(item.RuleCriteria),
			RuleEnabled:     types.BoolPointerValue(item.RuleEnabled),
			MatchingAssets:  int64OrNull(item.MatchingAssets),
			OnMatch:         map[string]types.String{},
		}
		for k, v := range item.OnMatch {
			rule.OnMatch[k] = types.StringValue(v)
		}
		data.TagRules = append(data.TagRules, rule)
		data.IDs = append(data.IDs, rule.ID)
	}

	data.Total = types.Int64Value(int64(len(items)))
	if total != nil {
		data.Total = types.Int64Value(*total)
	}
	data.Truncated = types.BoolValue(truncated)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

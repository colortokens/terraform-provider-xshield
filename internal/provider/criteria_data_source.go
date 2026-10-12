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

var _ datasource.DataSource = &CriteriaDataSource{}
var _ datasource.DataSourceWithConfigure = &CriteriaDataSource{}

func NewCriteriaDataSource() datasource.DataSource {
	return &CriteriaDataSource{}
}

type CriteriaDataSource struct {
	client *sdk.Xshield
}

type CriteriaDataSourceModel struct {
	Criteria                 types.String   `tfsdk:"criteria"`
	MatchingAssets           types.Int64    `tfsdk:"matching_assets"`
	SampleAssetNames         []types.String `tfsdk:"sample_asset_names"`
	CanonicalSegmentCriteria types.String   `tfsdk:"canonical_segment_criteria"`
}

func (d *CriteriaDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_criteria"
}

func (d *CriteriaDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Checks a criteria against the tenant and reports how many assets it selects.\n\n" +
			"Use it to see the size of a selection before a segment is created, rather than after. " +
			"An invalid criteria fails the plan with the parser's own explanation.\n\n" +
			"A criteria that the asset search accepts is not guaranteed to be accepted by a segment: segments " +
			"take a strict subset of the grammar, allowing only `=`, `!=`, `IN`, `NOT IN`, `AND` and parentheses " +
			"over core tag fields. `canonical_segment_criteria` shows the form a segment would store.",
		Attributes: map[string]schema.Attribute{
			"criteria": criteriaAttribute(true, "The criteria to check, written against the asset scope."),
			"matching_assets": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of assets the criteria selects right now.",
			},
			"sample_asset_names": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Names of up to twenty matching assets, to confirm the selection is the intended one.",
			},
			"canonical_segment_criteria": schema.StringAttribute{
				Computed: true,
				Description: "The criteria as a segment would store it. A criteria that does not mention " +
					"managedby is wrapped with the managedby clause the backend appends.",
			},
		},
	}
}

func (d *CriteriaDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *CriteriaDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CriteriaDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	const sampleSize = 20
	request := operations.ListAssetsRequest{
		ComputeTotal: computeTotalOn,
		SearchInput: shared.SearchInput{
			Criteria:   data.Criteria.ValueString(),
			Pagination: searchPagination(pageRequest{Limit: sampleSize, Offset: 0}, "assetId"),
		},
	}

	res, err := d.client.Assets.ListAssets(ctx, request,
		operations.WithAcceptHeaderOverride(operations.AcceptHeaderEnumApplicationJson))
	if err != nil {
		resp.Diagnostics.AddError("Cannot evaluate the criteria", err.Error())
		return
	}
	if res.StatusCode != 200 {
		// A 400 here is the criteria parser rejecting the expression, and its
		// message names the offending field or literal.
		resp.Diagnostics.AddAttributeError(
			pathRootCriteria(),
			"The criteria was rejected",
			apiErrorDetail(res.ErrorResponse, res.RawResponse))
		return
	}

	data.CanonicalSegmentCriteria = types.StringValue(canonicalSegmentCriteria(data.Criteria.ValueString()))
	data.SampleAssetNames = []types.String{}
	data.MatchingAssets = types.Int64Value(0)

	if res.AssetSearchResults != nil {
		for _, asset := range res.AssetSearchResults.Items {
			data.SampleAssetNames = append(data.SampleAssetNames, types.StringValue(asset.AssetName))
		}
		if total := paginationTotal(res.AssetSearchResults.Metadata); total != nil {
			data.MatchingAssets = types.Int64Value(*total)
		} else {
			// Without a reported total the sample size is all that is known.
			data.MatchingAssets = types.Int64Value(int64(len(res.AssetSearchResults.Items)))
		}
	}

	if data.MatchingAssets.ValueInt64() == 0 {
		resp.Diagnostics.AddAttributeWarning(
			pathRootCriteria(),
			"The criteria matches no assets",
			fmt.Sprintf("%q is valid but selects nothing today. A segment built on it would have no members.",
				data.Criteria.ValueString()))
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

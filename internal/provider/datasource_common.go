package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// searchPageSize is the largest page the search endpoints honour. A limit above
// 1000 is silently reduced to the default of 100 rather than rejected, so asking
// for more than this loses rows without saying so.
const searchPageSize = int64(1000)

// computeTotalOn is the value sent for the computeTotal query parameter. Some
// routes parse it as a boolean and others only test that it is present, so a
// literal "true" satisfies both.
var computeTotalOn = sdk.String("true")

// pageRequest is one page of a search, ready to send.
type pageRequest struct {
	Limit  int64
	Offset int64
	Sort   []shared.OrderBy
}

// searchPagination builds the pagination block for a page.
//
// It always appends a tie-break column: offset paging is only stable when the
// sort is a total order, and every list endpoint except the asset search sorts
// on a non-unique column by default, so pages can otherwise repeat or skip rows.
func searchPagination(p pageRequest, tieBreakField string) *shared.PaginationConfig {
	sort := append([]shared.OrderBy{}, p.Sort...)
	seen := false
	for _, o := range sort {
		if o.Field != nil && *o.Field == tieBreakField {
			seen = true
		}
	}
	if !seen && tieBreakField != "" {
		sort = append(sort, shared.OrderBy{Field: sdk.String(tieBreakField), Order: shared.SortOrderAsc.ToPointer()})
	}
	return &shared.PaginationConfig{
		Limit:  sdk.Int64(p.Limit),
		Offset: sdk.Int64(p.Offset),
		Sort:   sort,
	}
}

// collectPages walks a search endpoint until it runs out of rows, or until
// maxResults have been gathered when that is set above zero.
//
// fetch reports the rows on one page and the total the endpoint claims, if it
// reported one.
func collectPages[T any](
	ctx context.Context,
	maxResults int64,
	fetch func(ctx context.Context, page pageRequest) (items []T, total *int64, err error),
) (collected []T, total *int64, truncated bool, err error) {
	for offset := int64(0); ; offset += searchPageSize {
		limit := searchPageSize
		if maxResults > 0 {
			remaining := maxResults - int64(len(collected))
			if remaining <= 0 {
				return collected, total, true, nil
			}
			if remaining < limit {
				limit = remaining
			}
		}

		items, pageTotal, err := fetch(ctx, pageRequest{Limit: limit, Offset: offset})
		if err != nil {
			return nil, nil, false, err
		}
		if pageTotal != nil {
			total = pageTotal
		}
		collected = append(collected, items...)

		// A short page means the end of the result set.
		if int64(len(items)) < limit {
			return collected, total, false, nil
		}
		if maxResults > 0 && int64(len(collected)) >= maxResults {
			// Whether more exist is only knowable from the total.
			more := total == nil || *total > int64(len(collected))
			return collected, total, more, nil
		}
	}
}

func paginationTotal(meta *shared.PaginationSummary) *int64 {
	if meta == nil {
		return nil
	}
	return meta.Total
}

// configureDataSourceClient performs the ProviderData assertion every data
// source repeats.
func configureDataSourceClient(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) *sdk.Xshield {
	if req.ProviderData == nil {
		return nil
	}
	client, ok := req.ProviderData.(*sdk.Xshield)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *sdk.Xshield, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return nil
	}
	return client
}

// criteriaAttribute is the search expression every list data source takes.
func criteriaAttribute(required bool, description string) schema.StringAttribute {
	return schema.StringAttribute{
		Required:    required,
		Optional:    !required,
		Description: description,
	}
}

// maxResultsAttribute bounds a result set that could otherwise be very large.
// Left unset the data source reads every match.
func maxResultsAttribute() schema.Int64Attribute {
	return schema.Int64Attribute{
		Optional: true,
		Description: "Stop after this many results. Left unset, every match is read. " +
			"When a limit truncates the result set, `truncated` is true.",
	}
}

func truncatedAttribute() schema.BoolAttribute {
	return schema.BoolAttribute{
		Computed:    true,
		Description: "True when `max_results` stopped the read before the end of the result set.",
	}
}

func totalAttribute(what string) schema.Int64Attribute {
	return schema.Int64Attribute{
		Computed:    true,
		Description: fmt.Sprintf("Total number of %s matching the criteria, as reported by the API.", what),
	}
}

func idsAttribute(what string) schema.ListAttribute {
	return schema.ListAttribute{
		Computed:    true,
		ElementType: types.StringType,
		Description: fmt.Sprintf("Ids of the matching %s, in the same order as the detailed list. Convenient for `for_each`.", what),
	}
}

// criteriaOrMatchAll returns the criteria to send, defaulting to the match-all
// expression when the practitioner did not narrow the search.
func criteriaOrMatchAll(v types.String) string {
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return "*"
	}
	return v.ValueString()
}

func stringList(values []string) []types.String {
	out := make([]types.String, 0, len(values))
	for _, v := range values {
		out = append(out, types.StringValue(v))
	}
	return out
}

func int64OrNull(v *int64) types.Int64 {
	return types.Int64PointerValue(v)
}

// apiErrorDetail renders the backend's error body, which carries the parser's
// explanation of a rejected criteria under "details".
func apiErrorDetail(errResp *shared.ErrorResponse, raw *http.Response) string {
	if errResp != nil {
		message := ""
		if errResp.Message != nil {
			message = *errResp.Message
		}
		if issues, ok := errResp.Details["issues"]; ok {
			return fmt.Sprintf("%s: %v", message, issues)
		}
		if len(errResp.Details) > 0 {
			return fmt.Sprintf("%s: %v", message, errResp.Details)
		}
		if message != "" {
			return message
		}
	}
	if raw != nil {
		return debugResponse(raw)
	}
	return "the API returned no error detail"
}

func pathRootCriteria() path.Path { return path.Root("criteria") }

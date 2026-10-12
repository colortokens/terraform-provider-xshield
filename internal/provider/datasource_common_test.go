package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// A malformed schema is only rejected when Terraform asks for it, so a mistake
// in any resource or data source would otherwise surface as a runtime panic in
// front of a practitioner rather than a test failure here.
func TestProviderSchemasAreValid(t *testing.T) {
	t.Parallel()
	server := providerserver.NewProtocol6(New("test")())()

	resp, err := server.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema: %v", err)
	}
	for _, d := range resp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Errorf("%s: %s", d.Summary, d.Detail)
		}
	}

	for _, name := range []string{
		"xshield_policy_deployment",
	} {
		if _, ok := resp.ResourceSchemas[name]; !ok {
			t.Errorf("resource %s is not registered", name)
		}
	}

	for _, name := range []string{
		"xshield_assets", "xshield_criteria", "xshield_fields", "xshield_field_values",
		"xshield_named_networks", "xshield_open_ports", "xshield_paths",
		"xshield_segments", "xshield_tag_rules", "xshield_templates", "xshield_work_request",
	} {
		if _, ok := resp.DataSourceSchemas[name]; !ok {
			t.Errorf("data source %s is not registered", name)
		}
	}
}

func TestCollectPagesWalksEveryPage(t *testing.T) {
	t.Parallel()
	// 2500 rows over a page size of 1000 is three requests, the last one short.
	const available = 2500
	var requested []pageRequest

	items, total, truncated, err := collectPages(context.Background(), 0,
		func(_ context.Context, page pageRequest) ([]int, *int64, error) {
			requested = append(requested, page)
			var got []int
			for i := page.Offset; i < page.Offset+page.Limit && i < available; i++ {
				got = append(got, int(i))
			}
			reported := int64(available)
			return got, &reported, nil
		})
	if err != nil {
		t.Fatalf("collectPages: %v", err)
	}
	if len(items) != available {
		t.Errorf("collected %d rows, want %d", len(items), available)
	}
	if truncated {
		t.Error("an unbounded read should not report truncation")
	}
	if total == nil || *total != available {
		t.Errorf("total = %v, want %d", total, available)
	}
	if len(requested) != 3 {
		t.Fatalf("made %d requests, want 3", len(requested))
	}
	for i, page := range requested {
		if want := int64(i) * searchPageSize; page.Offset != want {
			t.Errorf("request %d used offset %d, want %d", i, page.Offset, want)
		}
	}
}

func TestCollectPagesStopsOnAShortPage(t *testing.T) {
	t.Parallel()
	calls := 0
	items, _, truncated, err := collectPages(context.Background(), 0,
		func(_ context.Context, page pageRequest) ([]int, *int64, error) {
			calls++
			return []int{1, 2, 3}, nil, nil
		})
	if err != nil {
		t.Fatalf("collectPages: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d requests, want 1; a page shorter than the limit is the end", calls)
	}
	if len(items) != 3 || truncated {
		t.Errorf("items=%d truncated=%v", len(items), truncated)
	}
}

func TestCollectPagesHonoursMaxResults(t *testing.T) {
	t.Parallel()
	items, _, truncated, err := collectPages(context.Background(), 10,
		func(_ context.Context, page pageRequest) ([]int, *int64, error) {
			if page.Limit != 10 {
				t.Errorf("asked for %d rows, want the request capped to max_results", page.Limit)
			}
			got := make([]int, page.Limit)
			reported := int64(500)
			return got, &reported, nil
		})
	if err != nil {
		t.Fatalf("collectPages: %v", err)
	}
	if len(items) != 10 {
		t.Errorf("collected %d rows, want 10", len(items))
	}
	if !truncated {
		t.Error("stopping short of the reported total must be reported as truncated")
	}
}

func TestCollectPagesReportsTheFetchError(t *testing.T) {
	t.Parallel()
	_, _, _, err := collectPages(context.Background(), 0,
		func(_ context.Context, page pageRequest) ([]int, *int64, error) {
			return nil, nil, fmt.Errorf("the API answered 400")
		})
	if err == nil {
		t.Fatal("a failed page must fail the read rather than return a partial set")
	}
}

func TestSearchPaginationAddsATieBreak(t *testing.T) {
	t.Parallel()
	// Offset paging repeats or skips rows unless the sort is a total order, and
	// only the asset search adds a unique column by itself.
	p := searchPagination(pageRequest{Limit: 100, Offset: 200}, "assetId")
	if p.Limit == nil || *p.Limit != 100 || p.Offset == nil || *p.Offset != 200 {
		t.Fatalf("limit/offset = %v/%v", p.Limit, p.Offset)
	}
	if len(p.Sort) != 1 || p.Sort[0].Field == nil || *p.Sort[0].Field != "assetId" {
		t.Fatalf("sort = %+v, want a single assetId column", p.Sort)
	}
	if p.Sort[0].Order == nil || *p.Sort[0].Order != "Asc" {
		t.Errorf("sort order = %v, want Asc", p.Sort[0].Order)
	}
}

func TestSearchPaginationKeepsAnExplicitTieBreak(t *testing.T) {
	t.Parallel()
	existing := pageRequest{Limit: 10, Sort: []shared.OrderBy{
		{Field: sdk.String("assetId"), Order: shared.SortOrderDesc.ToPointer()},
	}}
	p := searchPagination(existing, "assetId")
	if len(p.Sort) != 1 {
		t.Fatalf("sort = %+v, want the caller's column left alone", p.Sort)
	}
	if *p.Sort[0].Order != "Desc" {
		t.Errorf("the caller's sort direction was overwritten: %v", *p.Sort[0].Order)
	}
}

func TestCriteriaOrMatchAll(t *testing.T) {
	t.Parallel()
	if got := criteriaOrMatchAll(types.StringNull()); got != "*" {
		t.Errorf("an unset criteria should match everything, got %q", got)
	}
	if got := criteriaOrMatchAll(types.StringValue("")); got != "*" {
		t.Errorf("an empty criteria should match everything, got %q", got)
	}
	if got := criteriaOrMatchAll(types.StringValue("environment = 'prod'")); got != "environment = 'prod'" {
		t.Errorf("criteria = %q", got)
	}
}

func TestWorkRequestIsTerminal(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]bool{
		"Completed":  true,
		"Cancelled":  true,
		"Superseded": true,
		"Pending":    false,
		"InProgress": false,
		// Retry is not terminal: the work is still scheduled to run again.
		"Retry": false,
	} {
		if got := workRequestIsTerminal(status); got != want {
			t.Errorf("workRequestIsTerminal(%q) = %v, want %v", status, got, want)
		}
	}
}

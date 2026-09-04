package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CanonicalCriteriaModifier rewrites a planned segment criteria into the form
// the asset service stores, so the value in config, plan, state and the API all
// agree and a diff means the segment really changed.
func CanonicalCriteriaModifier() planmodifier.String {
	return &canonicalCriteriaModifier{}
}

type canonicalCriteriaModifier struct{}

func (m *canonicalCriteriaModifier) Description(ctx context.Context) string {
	return "Appends the managedby clause the backend adds, so the stored criteria matches the plan"
}

func (m *canonicalCriteriaModifier) MarkdownDescription(ctx context.Context) string {
	return "Appends the `managedby` clause the backend adds, so the stored criteria matches the plan"
}

func (m *canonicalCriteriaModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	resp.PlanValue = types.StringValue(canonicalSegmentCriteria(req.PlanValue.ValueString()))
}

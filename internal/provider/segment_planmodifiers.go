package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// AppendManagedByModifier returns a plan modifier that appends the managedby condition to criteria
func AppendManagedByModifier() planmodifier.String {
	return &appendManagedByModifier{}
}

type appendManagedByModifier struct{}

func (m *appendManagedByModifier) Description(ctx context.Context) string {
	return "Appends ' AND 'managedby' in ('colortokens')' to the criteria if not already present"
}

func (m *appendManagedByModifier) MarkdownDescription(ctx context.Context) string {
	return "Appends ` AND 'managedby' in ('colortokens')` to the criteria if not already present"
}

func (m *appendManagedByModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the plan value is null or unknown, do nothing
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}

	planValue := req.PlanValue.ValueString()

	// Check if the managedby condition is already present
	if !strings.Contains(planValue, "'managedby' in ('colortokens')") {
		// Append the managedby condition
		modifiedValue := planValue + " AND 'managedby' in ('colortokens')"
		tflog.Debug(ctx, "AppendManagedByModifier: Appending managedby condition", map[string]interface{}{
			"original": planValue,
			"modified": modifiedValue,
		})
		resp.PlanValue = types.StringValue(modifiedValue)
	}
}

// NormalizeDeploymentModeModifier returns a plan modifier that converts "enforce" to "enforced"
func NormalizeDeploymentModeModifier() planmodifier.String {
	return &normalizeDeploymentModeModifier{}
}

type normalizeDeploymentModeModifier struct{}

func (m *normalizeDeploymentModeModifier) Description(ctx context.Context) string {
	return "Converts 'enforce' to 'enforced' to match API expectations"
}

func (m *normalizeDeploymentModeModifier) MarkdownDescription(ctx context.Context) string {
	return "Converts `enforce` to `enforced` to match API expectations"
}

func (m *normalizeDeploymentModeModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the plan value is null or unknown, do nothing
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}

	planValue := req.PlanValue.ValueString()

	// Convert "enforce" to "enforced"
	if planValue == "enforce" {
		tflog.Debug(ctx, "NormalizeDeploymentModeModifier: Converting enforce to enforced")
		resp.PlanValue = types.StringValue("enforced")
	}
}

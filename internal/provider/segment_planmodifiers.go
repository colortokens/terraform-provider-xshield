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

	// Check if the managedby field is mentioned in any form
	// Look for common patterns like 'managedby' = or 'managedby' in
	if strings.Contains(strings.ToLower(planValue), "'managedby'") ||
		strings.Contains(strings.ToLower(planValue), "\"managedby\"") {
		// managedby is already specified in some form, honor it
		tflog.Debug(ctx, "AppendManagedByModifier: managedby already specified, not modifying", map[string]interface{}{
			"criteria": planValue,
		})
		return
	}

	// managedby not found, append the default condition
	modifiedValue := planValue + " AND 'managedby' in ('colortokens')"
	tflog.Debug(ctx, "AppendManagedByModifier: Appending managedby condition", map[string]interface{}{
		"original": planValue,
		"modified": modifiedValue,
	})
	resp.PlanValue = types.StringValue(modifiedValue)
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

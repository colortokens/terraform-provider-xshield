package provider

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// matchingAssets is a count the backend derives from the membership table. The
// resource does not model it, so it must not appear in a write body either.
func TestTagRuleWriteBodyOmitsMatchingAssets(t *testing.T) {
	t.Parallel()

	model := TagRuleResourceModel{
		ID:           types.StringValue("11111111-2222-3333-4444-555555555555"),
		RuleName:     types.StringValue("tag-payroll"),
		RuleCriteria: types.StringValue("'application' in ('payroll')"),
		RuleEnabled:  types.BoolValue(true),
		OnMatch:      map[string]types.String{"environment": types.StringValue("prod")},
	}

	body, err := json.Marshal(model.ToSharedTagRule())
	if err != nil {
		t.Fatalf("marshal tag rule: %v", err)
	}
	if strings.Contains(string(body), "matchingAssets") {
		t.Errorf("write body carries matchingAssets, which the resource no longer models: %s", body)
	}

	// The rest of the body must survive the removal.
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("unmarshal tag rule body: %v", err)
	}
	for _, key := range []string{"ruleName", "ruleCriteria", "ruleEnabled", "onMatch"} {
		if _, ok := sent[key]; !ok {
			t.Errorf("write body lost %q: %s", key, body)
		}
	}
}

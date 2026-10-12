package provider

import (
	"context"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCanonicalSegmentCriteria(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		in           string
		want         string
		whyItMatters string
	}{
		{
			name:         "adds the clause the backend adds",
			in:           "application in ('payroll1', 'hr')",
			want:         "(application in ('payroll1', 'hr')) AND 'managedby' in ('colortokens')",
			whyItMatters: "this exact string is what GET returns, per tagset_test.go in the backend",
		},
		{
			name: "leaves a criteria that already constrains managedby",
			in:   "application = 'payroll' AND managedby in ('crowdstrike')",
			want: "application = 'payroll' AND managedby in ('crowdstrike')",
		},
		{
			name:         "recognises the quoted field form",
			in:           "(application = 'payroll') AND 'managedby' in ('colortokens')",
			want:         "(application = 'payroll') AND 'managedby' in ('colortokens')",
			whyItMatters: "applying the rewrite twice would produce a criteria that never matches state",
		},
		{
			name:         "treats managedby inside a value as a value",
			in:           "application = 'managedby'",
			want:         "(application = 'managedby') AND 'managedby' in ('colortokens')",
			whyItMatters: "a value that merely reads like the field must not suppress the rewrite",
		},
		{
			name: "is a no-op on an empty criteria",
			in:   "",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalSegmentCriteria(tc.in); got != tc.want {
				t.Errorf("canonicalSegmentCriteria(%q)\n got: %q\nwant: %q\n%s", tc.in, got, tc.want, tc.whyItMatters)
			}
		})
	}
}

func TestCanonicalSegmentCriteriaIsIdempotent(t *testing.T) {
	t.Parallel()
	// Create, Update and every plan run plumb the value through this function.
	// Appending twice would make the resource permanently out of sync.
	once := canonicalSegmentCriteria("environment = 'prod'")
	if twice := canonicalSegmentCriteria(once); twice != once {
		t.Errorf("second pass changed the criteria\n once: %q\ntwice: %q", once, twice)
	}
}

func TestCriteriaReferencesManagedBy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"managedby = 'colortokens'", true},
		{"'managedby' in ('colortokens')", true},
		{`"managedby" in ('colortokens')`, true},
		{"MANAGEDBY in ('colortokens')", true},
		{"managedby not in ('crowdstrike')", true},
		{"application = 'x'", false},
		{"application = 'managedby'", false},
		{"application = 'managedby-owned'", false},
		{"", false},
	} {
		if got := criteriaReferencesManagedBy(tc.in); got != tc.want {
			t.Errorf("criteriaReferencesManagedBy(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeAutoSyncDeploymentMode(t *testing.T) {
	t.Parallel()
	// The endpoint accepts test/enforce/disable and reads back
	// under-test/enforced/disabled. Showing the read vocabulary in state made
	// every plan want to rewrite a setting that had not changed.
	for read, want := range map[string]string{
		"under-test": "test",
		"enforced":   "enforce",
		"disabled":   "disable",
	} {
		if got := normalizeAutoSyncDeploymentMode(&read); got.ValueString() != want {
			t.Errorf("normalizeAutoSyncDeploymentMode(%q) = %q, want %q", read, got.ValueString(), want)
		}
	}
	if got := normalizeAutoSyncDeploymentMode(nil); !got.IsNull() {
		t.Errorf("a nil mode should be null, got %q", got.ValueString())
	}
}

func TestAutoSyncSentinelToNull(t *testing.T) {
	t.Parallel()
	sentinel := int64(-1)
	if got := autoSyncSentinelToNull(&sentinel); !got.IsNull() {
		t.Errorf("-1 should read as null, got %d", got.ValueInt64())
	}
	real := int64(60)
	if got := autoSyncSentinelToNull(&real); got.ValueInt64() != 60 {
		t.Errorf("60 should read as 60, got %v", got)
	}
	if got := autoSyncSentinelToNull(nil); !got.IsNull() {
		t.Error("nil should read as null")
	}
}

func TestSegmentRefreshNormalizesAutomation(t *testing.T) {
	t.Parallel()
	mode := "under-test"
	sentinel := int64(-1)
	criteria := "(application = 'payroll') AND 'managedby' in ('colortokens')"
	name := "payroll"

	var model SegmentResourceModel
	model.RefreshFromSharedTagBasedPolicyResponse(&shared.TagBasedPolicyResponse{
		TagBasedPolicyName:                &name,
		Criteria:                          &criteria,
		InboundAutoSyncDeploymentMode:     &mode,
		InboundAutoSyncIntervalMinutes:    &sentinel,
		InboundAutoSyncViolationThreshold: &sentinel,
	})

	if got := model.InboundAutoSyncDeploymentMode.ValueString(); got != "test" {
		t.Errorf("inbound_auto_sync_deployment_mode = %q, want the write vocabulary %q", got, "test")
	}
	if !model.InboundAutoSyncIntervalMinutes.IsNull() {
		t.Errorf("inbound_auto_sync_interval_minutes = %v, want null for the -1 sentinel",
			model.InboundAutoSyncIntervalMinutes)
	}
	if !model.InboundAutoSyncViolationThreshold.IsNull() {
		t.Errorf("inbound_auto_sync_violation_threshold = %v, want null for the -1 sentinel",
			model.InboundAutoSyncViolationThreshold)
	}
	// Read used to overwrite the criteria with whatever was already in state,
	// which hid every portal edit.
	if got := model.Criteria.ValueString(); got != criteria {
		t.Errorf("criteria = %q, want the value the API returned %q", got, criteria)
	}

}

// The two policy floors take different value sets: inbound has intermediate port
// states, outbound is binary. Without validators a cross-direction value passes
// plan and is only refused by the API at apply.
func TestSegmentPolicyFloorsRejectCrossDirectionValues(t *testing.T) {
	t.Parallel()

	schemaResp := &resource.SchemaResponse{}
	NewSegmentResource().Schema(context.Background(), resource.SchemaRequest{}, schemaResp)

	run := func(t *testing.T, attrName, value string) diag.Diagnostics {
		t.Helper()
		attr, ok := schemaResp.Schema.Attributes[attrName].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s is not a StringAttribute", attrName)
		}
		if len(attr.Validators) == 0 {
			t.Fatalf("%s has no validators, so bad values reach the API", attrName)
		}
		resp := &validator.StringResponse{}
		for _, v := range attr.Validators {
			v.ValidateString(context.Background(), validator.StringRequest{
				Path:        path.Root(attrName),
				ConfigValue: types.StringValue(value),
			}, resp)
		}
		return resp.Diagnostics
	}

	const inbound = "lowest_inbound_segment_asset_policy_status"
	const outbound = "lowest_outbound_segment_asset_policy_status"

	for _, tc := range []struct {
		attr, value string
		wantError   bool
	}{
		{inbound, "allow-open-ports", false},
		{inbound, "allow-active-ports", false},
		{inbound, "zerotrust", false},
		{inbound, "default-allow", false},
		// Outbound is binary; the inbound-only port states must not be accepted.
		{outbound, "allow-open-ports", true},
		{outbound, "allow-active-ports", true},
		{outbound, "zerotrust", false},
		{outbound, "default-allow", false},
		{inbound, "enforced", true},
	} {
		t.Run(tc.attr+"="+tc.value, func(t *testing.T) {
			diags := run(t, tc.attr, tc.value)
			if got := diags.HasError(); got != tc.wantError {
				t.Errorf("%s = %q: error=%v, want error=%v (%v)",
					tc.attr, tc.value, got, tc.wantError, diags)
			}
		})
	}
}

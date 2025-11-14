package provider

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

// ToSharedTagBasedPolicyMetadata returns a TagBasedPolicy with only the metadata fields set
// This is used for updating just the metadata of a segment
func (r *SegmentResourceModel) ToSharedTagBasedPolicyMetadata() *shared.TagBasedPolicy {
	id := new(string)
	if !r.ID.IsUnknown() && !r.ID.IsNull() {
		*id = r.ID.ValueString()
	} else {
		id = nil
	}
	description := new(string)
	if !r.Description.IsUnknown() && !r.Description.IsNull() {
		*description = r.Description.ValueString()
	} else {
		description = nil
	}
	tagBasedPolicyName := new(string)
	if !r.TagBasedPolicyName.IsUnknown() && !r.TagBasedPolicyName.IsNull() {
		*tagBasedPolicyName = r.TagBasedPolicyName.ValueString()
	} else {
		tagBasedPolicyName = nil
	}
	targetBreachImpactScore := new(int64)
	if !r.TargetBreachImpactScore.IsUnknown() && !r.TargetBreachImpactScore.IsNull() {
		*targetBreachImpactScore = r.TargetBreachImpactScore.ValueInt64()
	} else {
		targetBreachImpactScore = nil
	}
	timeline := new(int64)
	if !r.Timeline.IsUnknown() && !r.Timeline.IsNull() {
		*timeline = r.Timeline.ValueInt64()
	} else {
		timeline = nil
	}
	criteria := new(string)
	if !r.Criteria.IsUnknown() && !r.Criteria.IsNull() {
		*criteria = r.Criteria.ValueString()
	} else {
		criteria = nil
	}

	// Create a TagBasedPolicy with only the metadata fields
	out := shared.TagBasedPolicy{
		ID:                      id,
		Description:             description,
		TagBasedPolicyName:      tagBasedPolicyName,
		TargetBreachImpactScore: targetBreachImpactScore,
		Timeline:                timeline,
		Criteria:                criteria,
		// Explicitly set these to empty slices to avoid including them in the update
		Namednetworks: []shared.MetadataNamedNetworkReference{},
		Templates:     []shared.TemplateReference{},
	}
	return &out
}

// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type SummarizeField struct {
	Criteria         string  `json:"criteria"`
	FacetField       string  `json:"facetField"`
	FacetFieldFilter *string `json:"facetFieldFilter,omitempty"`
	Scope            *string `json:"scope,omitempty"`
}

func (o *SummarizeField) GetCriteria() string {
	if o == nil {
		return ""
	}
	return o.Criteria
}

func (o *SummarizeField) GetFacetField() string {
	if o == nil {
		return ""
	}
	return o.FacetField
}

func (o *SummarizeField) GetFacetFieldFilter() *string {
	if o == nil {
		return nil
	}
	return o.FacetFieldFilter
}

func (o *SummarizeField) GetScope() *string {
	if o == nil {
		return nil
	}
	return o.Scope
}

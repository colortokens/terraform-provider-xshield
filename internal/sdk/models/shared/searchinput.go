// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type SearchInput struct {
	Criteria    string            `json:"criteria"`
	FacetFields []string          `json:"facetFields,omitempty"`
	Pagination  *PaginationConfig `json:"pagination,omitempty"`
}

func (o *SearchInput) GetCriteria() string {
	if o == nil {
		return ""
	}
	return o.Criteria
}

func (o *SearchInput) GetFacetFields() []string {
	if o == nil {
		return nil
	}
	return o.FacetFields
}

func (o *SearchInput) GetPagination() *PaginationConfig {
	if o == nil {
		return nil
	}
	return o.Pagination
}

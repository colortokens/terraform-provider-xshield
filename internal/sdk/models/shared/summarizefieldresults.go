// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type SummarizeFieldResults struct {
	Facet *Facet `json:"Facet,omitempty"`
}

func (o *SummarizeFieldResults) GetFacet() *Facet {
	if o == nil {
		return nil
	}
	return o.Facet
}

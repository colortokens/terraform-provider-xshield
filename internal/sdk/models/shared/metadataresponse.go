// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

// MetadataResponse is the field catalogue returned by GET /api/fields.
//
// The handler answers with model.MetadataResponse, whose single member is
// serialised as "columns". The swagger annotation on that route claims
// TypeaheadSuggestions, which is a different shape and decodes to nothing.
type MetadataResponse struct {
	Columns map[string]MetadataColumnDescriptor `json:"columns,omitempty"`
}

func (o *MetadataResponse) GetColumns() map[string]MetadataColumnDescriptor {
	if o == nil {
		return nil
	}
	return o.Columns
}

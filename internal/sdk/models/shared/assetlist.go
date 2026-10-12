// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type AssetList struct {
	Items    []AssetPortInfo    `json:"items,omitempty"`
	Metadata *PaginationSummary `json:"metadata,omitempty"`
}

func (o *AssetList) GetItems() []AssetPortInfo {
	if o == nil {
		return nil
	}
	return o.Items
}

func (o *AssetList) GetMetadata() *PaginationSummary {
	if o == nil {
		return nil
	}
	return o.Metadata
}

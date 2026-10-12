// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

// Program - Program definition Represents a running process in the case of a VM / physical host or may represent a container in context of kubernetes services.
type Program struct {
	Image *string `json:"image,omitempty"`
	Name  string  `json:"name"`
	Path  *string `json:"path,omitempty"`
}

func (o *Program) GetImage() *string {
	if o == nil {
		return nil
	}
	return o.Image
}

func (o *Program) GetName() string {
	if o == nil {
		return ""
	}
	return o.Name
}

func (o *Program) GetPath() *string {
	if o == nil {
		return nil
	}
	return o.Path
}

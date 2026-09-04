// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type AppControlPendingChanges struct {
	AllowTemplates      []string `json:"allowTemplates,omitempty"`
	BlockTemplates      []string `json:"blockTemplates,omitempty"`
	ChangedApplications *int64   `json:"changedApplications,omitempty"`
}

func (o *AppControlPendingChanges) GetAllowTemplates() []string {
	if o == nil {
		return nil
	}
	return o.AllowTemplates
}

func (o *AppControlPendingChanges) GetBlockTemplates() []string {
	if o == nil {
		return nil
	}
	return o.BlockTemplates
}

func (o *AppControlPendingChanges) GetChangedApplications() *int64 {
	if o == nil {
		return nil
	}
	return o.ChangedApplications
}

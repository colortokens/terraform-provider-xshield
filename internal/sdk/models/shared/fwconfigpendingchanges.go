// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type FWConfigPendingChanges struct {
	FwCoexistenceCfgUpdatePending *bool `json:"fwCoexistenceCfgUpdatePending,omitempty"`
	IPV6BlanketAllow              *bool `json:"IPV6BlanketAllow,omitempty"`
	IntranetChange                *bool `json:"intranetChange,omitempty"`
}

func (o *FWConfigPendingChanges) GetFwCoexistenceCfgUpdatePending() *bool {
	if o == nil {
		return nil
	}
	return o.FwCoexistenceCfgUpdatePending
}

func (o *FWConfigPendingChanges) GetIPV6BlanketAllow() *bool {
	if o == nil {
		return nil
	}
	return o.IPV6BlanketAllow
}

func (o *FWConfigPendingChanges) GetIntranetChange() *bool {
	if o == nil {
		return nil
	}
	return o.IntranetChange
}

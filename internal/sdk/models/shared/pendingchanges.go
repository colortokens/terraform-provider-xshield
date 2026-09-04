// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type PendingChanges struct {
	AllowTemplates           []string `json:"allowTemplates,omitempty"`
	AssetPolicySyncPending   *bool    `json:"assetPolicySyncPending,omitempty"`
	BlockTemplates           []string `json:"blockTemplates,omitempty"`
	InternetPaths            *int64   `json:"internetPaths,omitempty"`
	InternetPorts            *int64   `json:"internetPorts,omitempty"`
	IntranetPaths            *int64   `json:"intranetPaths,omitempty"`
	IntranetPorts            *int64   `json:"intranetPorts,omitempty"`
	NamednetworkChange       []string `json:"namednetworkChange,omitempty"`
	PeerChange               *bool    `json:"peerChange,omitempty"`
	UnassignedAllowTemplates []string `json:"unassignedAllowTemplates,omitempty"`
	UnassignedBlockTemplates []string `json:"unassignedBlockTemplates,omitempty"`
}

func (o *PendingChanges) GetAllowTemplates() []string {
	if o == nil {
		return nil
	}
	return o.AllowTemplates
}

func (o *PendingChanges) GetAssetPolicySyncPending() *bool {
	if o == nil {
		return nil
	}
	return o.AssetPolicySyncPending
}

func (o *PendingChanges) GetBlockTemplates() []string {
	if o == nil {
		return nil
	}
	return o.BlockTemplates
}

func (o *PendingChanges) GetInternetPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.InternetPaths
}

func (o *PendingChanges) GetInternetPorts() *int64 {
	if o == nil {
		return nil
	}
	return o.InternetPorts
}

func (o *PendingChanges) GetIntranetPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.IntranetPaths
}

func (o *PendingChanges) GetIntranetPorts() *int64 {
	if o == nil {
		return nil
	}
	return o.IntranetPorts
}

func (o *PendingChanges) GetNamednetworkChange() []string {
	if o == nil {
		return nil
	}
	return o.NamednetworkChange
}

func (o *PendingChanges) GetPeerChange() *bool {
	if o == nil {
		return nil
	}
	return o.PeerChange
}

func (o *PendingChanges) GetUnassignedAllowTemplates() []string {
	if o == nil {
		return nil
	}
	return o.UnassignedAllowTemplates
}

func (o *PendingChanges) GetUnassignedBlockTemplates() []string {
	if o == nil {
		return nil
	}
	return o.UnassignedBlockTemplates
}

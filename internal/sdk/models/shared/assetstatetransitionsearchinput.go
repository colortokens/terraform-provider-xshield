// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type AssetStateTransitionSearchInput struct {
	Comment                   *string               `json:"comment,omitempty"`
	Criteria                  string                `json:"criteria"`
	InboundToDeploymentState  *AssetDeploymentState `json:"inboundToDeploymentState,omitempty"`
	OutboundToDeploymentState *AssetDeploymentState `json:"outboundToDeploymentState,omitempty"`
}

func (o *AssetStateTransitionSearchInput) GetComment() *string {
	if o == nil {
		return nil
	}
	return o.Comment
}

func (o *AssetStateTransitionSearchInput) GetCriteria() string {
	if o == nil {
		return ""
	}
	return o.Criteria
}

func (o *AssetStateTransitionSearchInput) GetInboundToDeploymentState() *AssetDeploymentState {
	if o == nil {
		return nil
	}
	return o.InboundToDeploymentState
}

func (o *AssetStateTransitionSearchInput) GetOutboundToDeploymentState() *AssetDeploymentState {
	if o == nil {
		return nil
	}
	return o.OutboundToDeploymentState
}

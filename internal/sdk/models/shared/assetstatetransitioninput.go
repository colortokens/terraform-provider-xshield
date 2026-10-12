// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type AssetStateTransitionInput struct {
	Comment                   *string               `json:"comment,omitempty"`
	InboundToDeploymentState  *AssetDeploymentState `json:"inboundToDeploymentState,omitempty"`
	OutboundToDeploymentState *AssetDeploymentState `json:"outboundToDeploymentState,omitempty"`
}

func (o *AssetStateTransitionInput) GetComment() *string {
	if o == nil {
		return nil
	}
	return o.Comment
}

func (o *AssetStateTransitionInput) GetInboundToDeploymentState() *AssetDeploymentState {
	if o == nil {
		return nil
	}
	return o.InboundToDeploymentState
}

func (o *AssetStateTransitionInput) GetOutboundToDeploymentState() *AssetDeploymentState {
	if o == nil {
		return nil
	}
	return o.OutboundToDeploymentState
}

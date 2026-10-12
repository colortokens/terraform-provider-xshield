// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type DeploymentPorts struct {
	ReviewedPorts   []DeploymentPort `json:"reviewedPorts,omitempty"`
	UnreviewedPorts []DeploymentPort `json:"unreviewedPorts,omitempty"`
}

func (o *DeploymentPorts) GetReviewedPorts() []DeploymentPort {
	if o == nil {
		return nil
	}
	return o.ReviewedPorts
}

func (o *DeploymentPorts) GetUnreviewedPorts() []DeploymentPort {
	if o == nil {
		return nil
	}
	return o.UnreviewedPorts
}

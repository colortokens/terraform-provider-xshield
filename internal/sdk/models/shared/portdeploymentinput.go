// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type PortDeploymentInput struct {
	Comment *string `json:"comment,omitempty"`
	// Deployment criteria
	DeploymentCriteria PortEnforceModeInput `json:"deploymentCriteria"`
	// Deployment plan
	DeploymentPlan DeploymentPlan `json:"deploymentPlan"`
}

func (o *PortDeploymentInput) GetComment() *string {
	if o == nil {
		return nil
	}
	return o.Comment
}

func (o *PortDeploymentInput) GetDeploymentCriteria() PortEnforceModeInput {
	if o == nil {
		return PortEnforceModeInput{}
	}
	return o.DeploymentCriteria
}

func (o *PortDeploymentInput) GetDeploymentPlan() DeploymentPlan {
	if o == nil {
		return DeploymentPlan{}
	}
	return o.DeploymentPlan
}

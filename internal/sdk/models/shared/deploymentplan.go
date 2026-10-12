// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type DeploymentPlan struct {
	// Keys are protocol strings like "TCP:22"
	Reviewed map[string]DeploymentConfig `json:"reviewed,omitempty"`
	// "*" key for unreviewed
	Unreviewed map[string]DeploymentConfig `json:"unreviewed,omitempty"`
}

func (o *DeploymentPlan) GetReviewed() map[string]DeploymentConfig {
	if o == nil {
		return nil
	}
	return o.Reviewed
}

func (o *DeploymentPlan) GetUnreviewed() map[string]DeploymentConfig {
	if o == nil {
		return nil
	}
	return o.Unreviewed
}

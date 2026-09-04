// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type DeploymentConfig struct {
	BypassWarnings *bool          `json:"bypassWarnings,omitempty"`
	DeploymentMode DeploymentMode `json:"deploymentMode"`
	TargetAssets   *TargetAssets  `json:"targetAssets,omitempty"`
}

func (o *DeploymentConfig) GetBypassWarnings() *bool {
	if o == nil {
		return nil
	}
	return o.BypassWarnings
}

func (o *DeploymentConfig) GetDeploymentMode() DeploymentMode {
	if o == nil {
		return ""
	}
	return o.DeploymentMode
}

func (o *DeploymentConfig) GetTargetAssets() *TargetAssets {
	if o == nil {
		return nil
	}
	return o.TargetAssets
}

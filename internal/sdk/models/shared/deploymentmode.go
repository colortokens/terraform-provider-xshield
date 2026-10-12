// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

import (
	"encoding/json"
	"fmt"
)

type DeploymentMode string

const (
	DeploymentModeTest         DeploymentMode = "test"
	DeploymentModeIntranetTest DeploymentMode = "intranet-test"
	DeploymentModeEnforce      DeploymentMode = "enforce"
	DeploymentModeUndeploy     DeploymentMode = "undeploy"
)

func (e DeploymentMode) ToPointer() *DeploymentMode {
	return &e
}
func (e *DeploymentMode) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "test":
		fallthrough
	case "intranet-test":
		fallthrough
	case "enforce":
		fallthrough
	case "undeploy":
		*e = DeploymentMode(v)
		return nil
	default:
		return fmt.Errorf("invalid value for DeploymentMode: %v", v)
	}
}

// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

import (
	"encoding/json"
	"fmt"
)

type AssetDeploymentState string

const (
	AssetDeploymentStateEnabled  AssetDeploymentState = "enabled"
	AssetDeploymentStateDisabled AssetDeploymentState = "disabled"
)

func (e AssetDeploymentState) ToPointer() *AssetDeploymentState {
	return &e
}
func (e *AssetDeploymentState) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "enabled":
		fallthrough
	case "disabled":
		*e = AssetDeploymentState(v)
		return nil
	default:
		return fmt.Errorf("invalid value for AssetDeploymentState: %v", v)
	}
}

// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

import (
	"encoding/json"
	"fmt"
)

type TargetAssets string

const (
	TargetAssetsAll      TargetAssets = "all"
	TargetAssetsAffected TargetAssets = "affected"
)

func (e TargetAssets) ToPointer() *TargetAssets {
	return &e
}
func (e *TargetAssets) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "all":
		fallthrough
	case "affected":
		*e = TargetAssets(v)
		return nil
	default:
		return fmt.Errorf("invalid value for TargetAssets: %v", v)
	}
}

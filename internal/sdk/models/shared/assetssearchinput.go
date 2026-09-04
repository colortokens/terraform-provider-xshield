// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type AssetsSearchInput struct {
	Criteria            string            `json:"criteria"`
	DeployedByUserEmail *string           `json:"deployedByUserEmail,omitempty"`
	DeploymentMode      *DeploymentMode   `json:"deploymentMode,omitempty"`
	Direction           *string           `json:"direction,omitempty"`
	FromTime            *string           `json:"fromTime,omitempty"`
	HasViolations       *bool             `json:"hasViolations,omitempty"`
	MinDaysInTest       *int64            `json:"minDaysInTest,omitempty"`
	Pagination          *PaginationConfig `json:"pagination,omitempty"`
	Port                *string           `json:"port,omitempty"`
	Protocol            *string           `json:"protocol,omitempty"`
	TargetAssets        *TargetAssets     `json:"targetAssets,omitempty"`
	ToTime              *string           `json:"toTime,omitempty"`
	Useremail           *string           `json:"useremail,omitempty"`
	ViolationThreshold  *int64            `json:"violationThreshold,omitempty"`
}

func (o *AssetsSearchInput) GetCriteria() string {
	if o == nil {
		return ""
	}
	return o.Criteria
}

func (o *AssetsSearchInput) GetDeployedByUserEmail() *string {
	if o == nil {
		return nil
	}
	return o.DeployedByUserEmail
}

func (o *AssetsSearchInput) GetDeploymentMode() *DeploymentMode {
	if o == nil {
		return nil
	}
	return o.DeploymentMode
}

func (o *AssetsSearchInput) GetDirection() *string {
	if o == nil {
		return nil
	}
	return o.Direction
}

func (o *AssetsSearchInput) GetFromTime() *string {
	if o == nil {
		return nil
	}
	return o.FromTime
}

func (o *AssetsSearchInput) GetHasViolations() *bool {
	if o == nil {
		return nil
	}
	return o.HasViolations
}

func (o *AssetsSearchInput) GetMinDaysInTest() *int64 {
	if o == nil {
		return nil
	}
	return o.MinDaysInTest
}

func (o *AssetsSearchInput) GetPagination() *PaginationConfig {
	if o == nil {
		return nil
	}
	return o.Pagination
}

func (o *AssetsSearchInput) GetPort() *string {
	if o == nil {
		return nil
	}
	return o.Port
}

func (o *AssetsSearchInput) GetProtocol() *string {
	if o == nil {
		return nil
	}
	return o.Protocol
}

func (o *AssetsSearchInput) GetTargetAssets() *TargetAssets {
	if o == nil {
		return nil
	}
	return o.TargetAssets
}

func (o *AssetsSearchInput) GetToTime() *string {
	if o == nil {
		return nil
	}
	return o.ToTime
}

func (o *AssetsSearchInput) GetUseremail() *string {
	if o == nil {
		return nil
	}
	return o.Useremail
}

func (o *AssetsSearchInput) GetViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.ViolationThreshold
}

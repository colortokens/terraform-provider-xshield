// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type PortEnforceModeInput struct {
	Criteria            string  `json:"criteria"`
	DeployedByUserEmail *string `json:"deployedByUserEmail,omitempty"`
	Direction           *string `json:"direction,omitempty"`
	FromTime            *string `json:"fromTime,omitempty"`
	HasViolations       *bool   `json:"hasViolations,omitempty"`
	MinDaysInTest       *int64  `json:"minDaysInTest,omitempty"`
	ToTime              *string `json:"toTime,omitempty"`
	Useremail           *string `json:"useremail,omitempty"`
	ViolationThreshold  *int64  `json:"violationThreshold,omitempty"`
}

func (o *PortEnforceModeInput) GetCriteria() string {
	if o == nil {
		return ""
	}
	return o.Criteria
}

func (o *PortEnforceModeInput) GetDeployedByUserEmail() *string {
	if o == nil {
		return nil
	}
	return o.DeployedByUserEmail
}

func (o *PortEnforceModeInput) GetDirection() *string {
	if o == nil {
		return nil
	}
	return o.Direction
}

func (o *PortEnforceModeInput) GetFromTime() *string {
	if o == nil {
		return nil
	}
	return o.FromTime
}

func (o *PortEnforceModeInput) GetHasViolations() *bool {
	if o == nil {
		return nil
	}
	return o.HasViolations
}

func (o *PortEnforceModeInput) GetMinDaysInTest() *int64 {
	if o == nil {
		return nil
	}
	return o.MinDaysInTest
}

func (o *PortEnforceModeInput) GetToTime() *string {
	if o == nil {
		return nil
	}
	return o.ToTime
}

func (o *PortEnforceModeInput) GetUseremail() *string {
	if o == nil {
		return nil
	}
	return o.Useremail
}

func (o *PortEnforceModeInput) GetViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.ViolationThreshold
}

// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type PortTestModeInput struct {
	Criteria            string  `json:"criteria"`
	DeployedByUserEmail *string `json:"deployedByUserEmail,omitempty"`
	Direction           *string `json:"direction,omitempty"`
	FromTime            *string `json:"fromTime,omitempty"`
	ToTime              *string `json:"toTime,omitempty"`
	Useremail           *string `json:"useremail,omitempty"`
}

func (o *PortTestModeInput) GetCriteria() string {
	if o == nil {
		return ""
	}
	return o.Criteria
}

func (o *PortTestModeInput) GetDeployedByUserEmail() *string {
	if o == nil {
		return nil
	}
	return o.DeployedByUserEmail
}

func (o *PortTestModeInput) GetDirection() *string {
	if o == nil {
		return nil
	}
	return o.Direction
}

func (o *PortTestModeInput) GetFromTime() *string {
	if o == nil {
		return nil
	}
	return o.FromTime
}

func (o *PortTestModeInput) GetToTime() *string {
	if o == nil {
		return nil
	}
	return o.ToTime
}

func (o *PortTestModeInput) GetUseremail() *string {
	if o == nil {
		return nil
	}
	return o.Useremail
}

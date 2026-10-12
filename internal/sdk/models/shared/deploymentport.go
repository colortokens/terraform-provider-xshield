// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type DeploymentPort struct {
	AffectedAssetsCount    *int64 `json:"affectedAssetsCount,omitempty"`
	AffectedAvgDaysInTest  *int64 `json:"affectedAvgDaysInTest,omitempty"`
	AffectedViolationCount *int64 `json:"affectedViolationCount,omitempty"`
	AllAvgDaysInTest       *int64 `json:"allAvgDaysInTest,omitempty"`
	AllViolationCount      *int64 `json:"allViolationCount,omitempty"`
	IsDeploymentRequired   *bool  `json:"isDeploymentRequired,omitempty"`
	// Port number or range such as "80" or "8000-8100"
	ListenPort         *string `json:"listenPort,omitempty"`
	ListenPortName     *string `json:"listenPortName,omitempty"`
	ListenPortProtocol *string `json:"listenPortProtocol,omitempty"`
	Method             *string `json:"method,omitempty"`
	PortCategory       *string `json:"portCategory,omitempty"`
	URI                *string `json:"uri,omitempty"`
}

func (o *DeploymentPort) GetAffectedAssetsCount() *int64 {
	if o == nil {
		return nil
	}
	return o.AffectedAssetsCount
}

func (o *DeploymentPort) GetAffectedAvgDaysInTest() *int64 {
	if o == nil {
		return nil
	}
	return o.AffectedAvgDaysInTest
}

func (o *DeploymentPort) GetAffectedViolationCount() *int64 {
	if o == nil {
		return nil
	}
	return o.AffectedViolationCount
}

func (o *DeploymentPort) GetAllAvgDaysInTest() *int64 {
	if o == nil {
		return nil
	}
	return o.AllAvgDaysInTest
}

func (o *DeploymentPort) GetAllViolationCount() *int64 {
	if o == nil {
		return nil
	}
	return o.AllViolationCount
}

func (o *DeploymentPort) GetIsDeploymentRequired() *bool {
	if o == nil {
		return nil
	}
	return o.IsDeploymentRequired
}

func (o *DeploymentPort) GetListenPort() *string {
	if o == nil {
		return nil
	}
	return o.ListenPort
}

func (o *DeploymentPort) GetListenPortName() *string {
	if o == nil {
		return nil
	}
	return o.ListenPortName
}

func (o *DeploymentPort) GetListenPortProtocol() *string {
	if o == nil {
		return nil
	}
	return o.ListenPortProtocol
}

func (o *DeploymentPort) GetMethod() *string {
	if o == nil {
		return nil
	}
	return o.Method
}

func (o *DeploymentPort) GetPortCategory() *string {
	if o == nil {
		return nil
	}
	return o.PortCategory
}

func (o *DeploymentPort) GetURI() *string {
	if o == nil {
		return nil
	}
	return o.URI
}

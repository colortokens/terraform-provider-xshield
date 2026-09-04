// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

type AssetPortInfo struct {
	AssetID                      *string   `json:"assetId,omitempty"`
	AssetName                    *string   `json:"assetName,omitempty"`
	CandidateAssetPolicyState    *string   `json:"candidateAssetPolicyState,omitempty"`
	CurrentAssetPolicyState      *string   `json:"currentAssetPolicyState,omitempty"`
	DaysInTest                   *int64    `json:"daysInTest,omitempty"`
	DeploymentMode               *string   `json:"deploymentMode,omitempty"`
	HasViolations                *bool     `json:"hasViolations,omitempty"`
	InboundAssetPolicyMode       *string   `json:"inboundAssetPolicyMode,omitempty"`
	InboundAssetPolicyUpdatedAt  *SafeTime `json:"inboundAssetPolicyUpdatedAt,omitempty"`
	LastDeploymentTime           *SafeTime `json:"lastDeploymentTime,omitempty"`
	ListenPortEnforced           *string   `json:"listenPortEnforced,omitempty"`
	ListenPortReviewed           *string   `json:"listenPortReviewed,omitempty"`
	OutboundAssetPolicyMode      *string   `json:"outboundAssetPolicyMode,omitempty"`
	OutboundAssetPolicyUpdatedAt *SafeTime `json:"outboundAssetPolicyUpdatedAt,omitempty"`
	PortConflictExists           *bool     `json:"portConflictExists,omitempty"`
	PortPolicyDeployed           *bool     `json:"portPolicyDeployed,omitempty"`
	ViolationCount               *int64    `json:"violationCount,omitempty"`
}

func (o *AssetPortInfo) GetAssetID() *string {
	if o == nil {
		return nil
	}
	return o.AssetID
}

func (o *AssetPortInfo) GetAssetName() *string {
	if o == nil {
		return nil
	}
	return o.AssetName
}

func (o *AssetPortInfo) GetCandidateAssetPolicyState() *string {
	if o == nil {
		return nil
	}
	return o.CandidateAssetPolicyState
}

func (o *AssetPortInfo) GetCurrentAssetPolicyState() *string {
	if o == nil {
		return nil
	}
	return o.CurrentAssetPolicyState
}

func (o *AssetPortInfo) GetDaysInTest() *int64 {
	if o == nil {
		return nil
	}
	return o.DaysInTest
}

func (o *AssetPortInfo) GetDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.DeploymentMode
}

func (o *AssetPortInfo) GetHasViolations() *bool {
	if o == nil {
		return nil
	}
	return o.HasViolations
}

func (o *AssetPortInfo) GetInboundAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyMode
}

func (o *AssetPortInfo) GetInboundAssetPolicyUpdatedAt() *SafeTime {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyUpdatedAt
}

func (o *AssetPortInfo) GetLastDeploymentTime() *SafeTime {
	if o == nil {
		return nil
	}
	return o.LastDeploymentTime
}

func (o *AssetPortInfo) GetListenPortEnforced() *string {
	if o == nil {
		return nil
	}
	return o.ListenPortEnforced
}

func (o *AssetPortInfo) GetListenPortReviewed() *string {
	if o == nil {
		return nil
	}
	return o.ListenPortReviewed
}

func (o *AssetPortInfo) GetOutboundAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyMode
}

func (o *AssetPortInfo) GetOutboundAssetPolicyUpdatedAt() *SafeTime {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyUpdatedAt
}

func (o *AssetPortInfo) GetPortConflictExists() *bool {
	if o == nil {
		return nil
	}
	return o.PortConflictExists
}

func (o *AssetPortInfo) GetPortPolicyDeployed() *bool {
	if o == nil {
		return nil
	}
	return o.PortPolicyDeployed
}

func (o *AssetPortInfo) GetViolationCount() *int64 {
	if o == nil {
		return nil
	}
	return o.ViolationCount
}

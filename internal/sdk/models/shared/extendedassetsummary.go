// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/internal/utils"
	"time"
)

type ExtendedAssetSummary struct {
	AgentStatus                          *string            `json:"agentStatus,omitempty"`
	AgentVersion                         *string            `json:"agentVersion,omitempty"`
	AppControlAssetPolicyStatus          *string            `json:"appControlAssetPolicyStatus,omitempty"`
	AppControlAssetStatus                *string            `json:"appControlAssetStatus,omitempty"`
	AppControlAutoSyncDeploymentMode     *string            `json:"appControlAutoSyncDeploymentMode,omitempty"`
	AppControlAutoSyncIncludeViolations  *bool              `json:"appControlAutoSyncIncludeViolations,omitempty"`
	AppControlAutoSyncIntervalMinutes    *int64             `json:"appControlAutoSyncIntervalMinutes,omitempty"`
	AppControlAutoSyncViolationThreshold *int64             `json:"appControlAutoSyncViolationThreshold,omitempty"`
	AssetAvailability                    *string            `json:"assetAvailability,omitempty"`
	AssetID                              *string            `json:"assetId,omitempty"`
	AssetInternetFacing                  *bool              `json:"assetInternetFacing,omitempty"`
	AssetName                            string             `json:"assetName"`
	AssetRisk                            *string            `json:"assetRisk,omitempty"`
	AttackSurface                        *string            `json:"attackSurface,omitempty"`
	BlastRadius                          *string            `json:"blastRadius,omitempty"`
	BlockCustomIPs                       *string            `json:"blockCustomIPs,omitempty"`
	BlockMaliciousIPs                    *string            `json:"blockMaliciousIPs,omitempty"`
	BreachResponseLevel                  *string            `json:"breachResponseLevel,omitempty"`
	BusinessValue                        *string            `json:"businessValue,omitempty"`
	CisaAdvisories                       *int64             `json:"cisaAdvisories,omitempty"`
	CloudConnectorMode                   *string            `json:"cloudConnectorMode,omitempty"`
	ClusterIdentifier                    *string            `json:"clusterIdentifier,omitempty"`
	ContainerNamespace                   *string            `json:"containerNamespace,omitempty"`
	CoreTags                             map[string]string  `json:"coreTags,omitempty"`
	InboundAssetDeploymentState          *string            `json:"inboundAssetDeploymentState,omitempty"`
	InboundAssetPolicyMode               *string            `json:"inboundAssetPolicyMode,omitempty"`
	InboundAssetPolicyUpdatedAt          *time.Time         `json:"inboundAssetPolicyUpdatedAt,omitempty"`
	InboundAssetStatus                   *string            `json:"inboundAssetStatus,omitempty"`
	InboundAutoDeployEnabled             *bool              `json:"inboundAutoDeployEnabled,omitempty"`
	InboundAutoSyncDeploymentMode        *string            `json:"inboundAutoSyncDeploymentMode,omitempty"`
	InboundAutoSyncIncludeViolations     *bool              `json:"inboundAutoSyncIncludeViolations,omitempty"`
	InboundAutoSyncIntervalMinutes       *int64             `json:"inboundAutoSyncIntervalMinutes,omitempty"`
	InboundAutoSyncViolationThreshold    *int64             `json:"inboundAutoSyncViolationThreshold,omitempty"`
	Interfaces                           []NetworkInterface `json:"interfaces,omitempty"`
	IsFlowCollectorEdrType               *bool              `json:"isFlowCollectorEdrType,omitempty"`
	KernelVersion                        *string            `json:"kernelVersion,omitempty"`
	KnownExploitVulnerability            *string            `json:"knownExploitVulnerability,omitempty"`
	LastFWSynchronized                   *time.Time         `json:"lastFWSynchronized,omitempty"`
	LateralMovementAttacks               *int64             `json:"lateralMovementAttacks,omitempty"`
	LateralMovementTechniques            *int64             `json:"lateralMovementTechniques,omitempty"`
	LateralMovementVulnerability         *string            `json:"lateralMovementVulnerability,omitempty"`
	LoggedinUser                         *string            `json:"loggedinUser,omitempty"`
	LowestInboundAssetPolicyStatus       *string            `json:"lowestInboundAssetPolicyStatus,omitempty"`
	LowestOutboundAssetPolicyStatus      *string            `json:"lowestOutboundAssetPolicyStatus,omitempty"`
	ManagedBy                            *string            `json:"managedBy,omitempty"`
	MaximumCVSSScore                     *float64           `json:"maximumCVSSScore,omitempty"`
	MicroDeploymentCompatible            *bool              `json:"microDeploymentCompatible,omitempty"`
	MostRecentNewPath                    *time.Time         `json:"mostRecentNewPath,omitempty"`
	NewPathProcessingStopped             *bool              `json:"newPathProcessingStopped,omitempty"`
	OsName                               *string            `json:"osName,omitempty"`
	OutboundAssetDeploymentState         *string            `json:"outboundAssetDeploymentState,omitempty"`
	OutboundAssetPolicyMode              *string            `json:"outboundAssetPolicyMode,omitempty"`
	OutboundAssetPolicyUpdatedAt         *time.Time         `json:"outboundAssetPolicyUpdatedAt,omitempty"`
	OutboundAssetStatus                  *string            `json:"outboundAssetStatus,omitempty"`
	OutboundAutoDeployEnabled            *bool              `json:"outboundAutoDeployEnabled,omitempty"`
	OutboundAutoSyncDeploymentMode       *string            `json:"outboundAutoSyncDeploymentMode,omitempty"`
	OutboundAutoSyncIncludeViolations    *bool              `json:"outboundAutoSyncIncludeViolations,omitempty"`
	OutboundAutoSyncIntervalMinutes      *int64             `json:"outboundAutoSyncIntervalMinutes,omitempty"`
	OutboundAutoSyncViolationThreshold   *int64             `json:"outboundAutoSyncViolationThreshold,omitempty"`
	PendingAttackSurfaceChanges          *bool              `json:"pendingAttackSurfaceChanges,omitempty"`
	PendingBlastRadiusChanges            *bool              `json:"pendingBlastRadiusChanges,omitempty"`
	PendingFWConfigChanges               *bool              `json:"pendingFWConfigChanges,omitempty"`
	Platform                             *string            `json:"platform,omitempty"`
	SecurityPatches                      *int64             `json:"securityPatches,omitempty"`
	SerialNumber                         *string            `json:"serialNumber,omitempty"`
	TotalComments                        *int64             `json:"totalComments,omitempty"`
	TotalPaths                           *int64             `json:"totalPaths,omitempty"`
	TotalPorts                           *int64             `json:"totalPorts,omitempty"`
	Type                                 string             `json:"type"`
	UnreviewedPaths                      *int64             `json:"unreviewedPaths,omitempty"`
	UnreviewedPorts                      *int64             `json:"unreviewedPorts,omitempty"`
	VendorInfo                           *string            `json:"vendorInfo,omitempty"`
	Vulnerabilities                      *int64             `json:"vulnerabilities,omitempty"`
	VulnerabilitySeverity                *string            `json:"vulnerabilitySeverity,omitempty"`
}

func (e ExtendedAssetSummary) MarshalJSON() ([]byte, error) {
	return utils.MarshalJSON(e, "", false)
}

func (e *ExtendedAssetSummary) UnmarshalJSON(data []byte) error {
	if err := utils.UnmarshalJSON(data, &e, "", false, false); err != nil {
		return err
	}
	return nil
}

func (o *ExtendedAssetSummary) GetAgentStatus() *string {
	if o == nil {
		return nil
	}
	return o.AgentStatus
}

func (o *ExtendedAssetSummary) GetAgentVersion() *string {
	if o == nil {
		return nil
	}
	return o.AgentVersion
}

func (o *ExtendedAssetSummary) GetAppControlAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAssetPolicyStatus
}

func (o *ExtendedAssetSummary) GetAppControlAssetStatus() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAssetStatus
}

func (o *ExtendedAssetSummary) GetAppControlAutoSyncDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncDeploymentMode
}

func (o *ExtendedAssetSummary) GetAppControlAutoSyncIncludeViolations() *bool {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncIncludeViolations
}

func (o *ExtendedAssetSummary) GetAppControlAutoSyncIntervalMinutes() *int64 {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncIntervalMinutes
}

func (o *ExtendedAssetSummary) GetAppControlAutoSyncViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncViolationThreshold
}

func (o *ExtendedAssetSummary) GetAssetAvailability() *string {
	if o == nil {
		return nil
	}
	return o.AssetAvailability
}

func (o *ExtendedAssetSummary) GetAssetID() *string {
	if o == nil {
		return nil
	}
	return o.AssetID
}

func (o *ExtendedAssetSummary) GetAssetInternetFacing() *bool {
	if o == nil {
		return nil
	}
	return o.AssetInternetFacing
}

func (o *ExtendedAssetSummary) GetAssetName() string {
	if o == nil {
		return ""
	}
	return o.AssetName
}

func (o *ExtendedAssetSummary) GetAssetRisk() *string {
	if o == nil {
		return nil
	}
	return o.AssetRisk
}

func (o *ExtendedAssetSummary) GetAttackSurface() *string {
	if o == nil {
		return nil
	}
	return o.AttackSurface
}

func (o *ExtendedAssetSummary) GetBlastRadius() *string {
	if o == nil {
		return nil
	}
	return o.BlastRadius
}

func (o *ExtendedAssetSummary) GetBlockCustomIPs() *string {
	if o == nil {
		return nil
	}
	return o.BlockCustomIPs
}

func (o *ExtendedAssetSummary) GetBlockMaliciousIPs() *string {
	if o == nil {
		return nil
	}
	return o.BlockMaliciousIPs
}

func (o *ExtendedAssetSummary) GetBreachResponseLevel() *string {
	if o == nil {
		return nil
	}
	return o.BreachResponseLevel
}

func (o *ExtendedAssetSummary) GetBusinessValue() *string {
	if o == nil {
		return nil
	}
	return o.BusinessValue
}

func (o *ExtendedAssetSummary) GetCisaAdvisories() *int64 {
	if o == nil {
		return nil
	}
	return o.CisaAdvisories
}

func (o *ExtendedAssetSummary) GetCloudConnectorMode() *string {
	if o == nil {
		return nil
	}
	return o.CloudConnectorMode
}

func (o *ExtendedAssetSummary) GetClusterIdentifier() *string {
	if o == nil {
		return nil
	}
	return o.ClusterIdentifier
}

func (o *ExtendedAssetSummary) GetContainerNamespace() *string {
	if o == nil {
		return nil
	}
	return o.ContainerNamespace
}

func (o *ExtendedAssetSummary) GetCoreTags() map[string]string {
	if o == nil {
		return nil
	}
	return o.CoreTags
}

func (o *ExtendedAssetSummary) GetInboundAssetDeploymentState() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetDeploymentState
}

func (o *ExtendedAssetSummary) GetInboundAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyMode
}

func (o *ExtendedAssetSummary) GetInboundAssetPolicyUpdatedAt() *time.Time {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyUpdatedAt
}

func (o *ExtendedAssetSummary) GetInboundAssetStatus() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetStatus
}

func (o *ExtendedAssetSummary) GetInboundAutoDeployEnabled() *bool {
	if o == nil {
		return nil
	}
	return o.InboundAutoDeployEnabled
}

func (o *ExtendedAssetSummary) GetInboundAutoSyncDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncDeploymentMode
}

func (o *ExtendedAssetSummary) GetInboundAutoSyncIncludeViolations() *bool {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncIncludeViolations
}

func (o *ExtendedAssetSummary) GetInboundAutoSyncIntervalMinutes() *int64 {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncIntervalMinutes
}

func (o *ExtendedAssetSummary) GetInboundAutoSyncViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncViolationThreshold
}

func (o *ExtendedAssetSummary) GetInterfaces() []NetworkInterface {
	if o == nil {
		return nil
	}
	return o.Interfaces
}

func (o *ExtendedAssetSummary) GetIsFlowCollectorEdrType() *bool {
	if o == nil {
		return nil
	}
	return o.IsFlowCollectorEdrType
}

func (o *ExtendedAssetSummary) GetKernelVersion() *string {
	if o == nil {
		return nil
	}
	return o.KernelVersion
}

func (o *ExtendedAssetSummary) GetKnownExploitVulnerability() *string {
	if o == nil {
		return nil
	}
	return o.KnownExploitVulnerability
}

func (o *ExtendedAssetSummary) GetLastFWSynchronized() *time.Time {
	if o == nil {
		return nil
	}
	return o.LastFWSynchronized
}

func (o *ExtendedAssetSummary) GetLateralMovementAttacks() *int64 {
	if o == nil {
		return nil
	}
	return o.LateralMovementAttacks
}

func (o *ExtendedAssetSummary) GetLateralMovementTechniques() *int64 {
	if o == nil {
		return nil
	}
	return o.LateralMovementTechniques
}

func (o *ExtendedAssetSummary) GetLateralMovementVulnerability() *string {
	if o == nil {
		return nil
	}
	return o.LateralMovementVulnerability
}

func (o *ExtendedAssetSummary) GetLoggedinUser() *string {
	if o == nil {
		return nil
	}
	return o.LoggedinUser
}

func (o *ExtendedAssetSummary) GetLowestInboundAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.LowestInboundAssetPolicyStatus
}

func (o *ExtendedAssetSummary) GetLowestOutboundAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.LowestOutboundAssetPolicyStatus
}

func (o *ExtendedAssetSummary) GetManagedBy() *string {
	if o == nil {
		return nil
	}
	return o.ManagedBy
}

func (o *ExtendedAssetSummary) GetMaximumCVSSScore() *float64 {
	if o == nil {
		return nil
	}
	return o.MaximumCVSSScore
}

func (o *ExtendedAssetSummary) GetMicroDeploymentCompatible() *bool {
	if o == nil {
		return nil
	}
	return o.MicroDeploymentCompatible
}

func (o *ExtendedAssetSummary) GetMostRecentNewPath() *time.Time {
	if o == nil {
		return nil
	}
	return o.MostRecentNewPath
}

func (o *ExtendedAssetSummary) GetNewPathProcessingStopped() *bool {
	if o == nil {
		return nil
	}
	return o.NewPathProcessingStopped
}

func (o *ExtendedAssetSummary) GetOsName() *string {
	if o == nil {
		return nil
	}
	return o.OsName
}

func (o *ExtendedAssetSummary) GetOutboundAssetDeploymentState() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetDeploymentState
}

func (o *ExtendedAssetSummary) GetOutboundAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyMode
}

func (o *ExtendedAssetSummary) GetOutboundAssetPolicyUpdatedAt() *time.Time {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyUpdatedAt
}

func (o *ExtendedAssetSummary) GetOutboundAssetStatus() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetStatus
}

func (o *ExtendedAssetSummary) GetOutboundAutoDeployEnabled() *bool {
	if o == nil {
		return nil
	}
	return o.OutboundAutoDeployEnabled
}

func (o *ExtendedAssetSummary) GetOutboundAutoSyncDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncDeploymentMode
}

func (o *ExtendedAssetSummary) GetOutboundAutoSyncIncludeViolations() *bool {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncIncludeViolations
}

func (o *ExtendedAssetSummary) GetOutboundAutoSyncIntervalMinutes() *int64 {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncIntervalMinutes
}

func (o *ExtendedAssetSummary) GetOutboundAutoSyncViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncViolationThreshold
}

func (o *ExtendedAssetSummary) GetPendingAttackSurfaceChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingAttackSurfaceChanges
}

func (o *ExtendedAssetSummary) GetPendingBlastRadiusChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingBlastRadiusChanges
}

func (o *ExtendedAssetSummary) GetPendingFWConfigChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingFWConfigChanges
}

func (o *ExtendedAssetSummary) GetPlatform() *string {
	if o == nil {
		return nil
	}
	return o.Platform
}

func (o *ExtendedAssetSummary) GetSecurityPatches() *int64 {
	if o == nil {
		return nil
	}
	return o.SecurityPatches
}

func (o *ExtendedAssetSummary) GetSerialNumber() *string {
	if o == nil {
		return nil
	}
	return o.SerialNumber
}

func (o *ExtendedAssetSummary) GetTotalComments() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalComments
}

func (o *ExtendedAssetSummary) GetTotalPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalPaths
}

func (o *ExtendedAssetSummary) GetTotalPorts() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalPorts
}

func (o *ExtendedAssetSummary) GetType() string {
	if o == nil {
		return ""
	}
	return o.Type
}

func (o *ExtendedAssetSummary) GetUnreviewedPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.UnreviewedPaths
}

func (o *ExtendedAssetSummary) GetUnreviewedPorts() *int64 {
	if o == nil {
		return nil
	}
	return o.UnreviewedPorts
}

func (o *ExtendedAssetSummary) GetVendorInfo() *string {
	if o == nil {
		return nil
	}
	return o.VendorInfo
}

func (o *ExtendedAssetSummary) GetVulnerabilities() *int64 {
	if o == nil {
		return nil
	}
	return o.Vulnerabilities
}

func (o *ExtendedAssetSummary) GetVulnerabilitySeverity() *string {
	if o == nil {
		return nil
	}
	return o.VulnerabilitySeverity
}

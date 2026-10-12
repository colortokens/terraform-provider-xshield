// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

import (
	"encoding/json"
	"fmt"
)

type CurrentTrafficConfiguration string

const (
	CurrentTrafficConfigurationDisabled           CurrentTrafficConfiguration = "disabled"
	CurrentTrafficConfigurationEnableAll          CurrentTrafficConfiguration = "enable-all"
	CurrentTrafficConfigurationEnableInboundOnly  CurrentTrafficConfiguration = "enable-inbound-only"
	CurrentTrafficConfigurationEnableOutboundOnly CurrentTrafficConfiguration = "enable-outbound-only"
)

func (e CurrentTrafficConfiguration) ToPointer() *CurrentTrafficConfiguration {
	return &e
}
func (e *CurrentTrafficConfiguration) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "disabled":
		fallthrough
	case "enable-all":
		fallthrough
	case "enable-inbound-only":
		fallthrough
	case "enable-outbound-only":
		*e = CurrentTrafficConfiguration(v)
		return nil
	default:
		return fmt.Errorf("invalid value for CurrentTrafficConfiguration: %v", v)
	}
}

type AssetDetails struct {
	IPV6BlanketAllowStatus               *string                         `json:"IPV6BlanketAllowStatus,omitempty"`
	ActiveBreachModeTemplatesAssigned    *int64                          `json:"activeBreachModeTemplatesAssigned,omitempty"`
	AgentID                              *string                         `json:"agentId,omitempty"`
	AgentLastCheckInTime                 *SafeTime                       `json:"agentLastCheckInTime,omitempty"`
	AgentName                            *string                         `json:"agentName,omitempty"`
	AgentStatus                          *string                         `json:"agentStatus,omitempty"`
	AgentVersion                         *string                         `json:"agentVersion,omitempty"`
	AllowTemplatesAssigned               *int64                          `json:"allowTemplatesAssigned,omitempty"`
	AppControlAssetDeploymentState       *string                         `json:"appControlAssetDeploymentState,omitempty"`
	AppControlAssetPendingChanges        *AppControlPendingChanges       `json:"appControlAssetPendingChanges,omitempty"`
	AppControlAssetPolicyMode            *string                         `json:"appControlAssetPolicyMode,omitempty"`
	AppControlAssetPolicyStatus          *string                         `json:"appControlAssetPolicyStatus,omitempty"`
	AppControlAssetPolicyUpdatedAt       *SafeTime                       `json:"appControlAssetPolicyUpdatedAt,omitempty"`
	AppControlAssetStatus                *string                         `json:"appControlAssetStatus,omitempty"`
	AppControlAutoSyncDeploymentMode     *string                         `json:"appControlAutoSyncDeploymentMode,omitempty"`
	AppControlAutoSyncIncludeViolations  *bool                           `json:"appControlAutoSyncIncludeViolations,omitempty"`
	AppControlAutoSyncIntervalMinutes    *int64                          `json:"appControlAutoSyncIntervalMinutes,omitempty"`
	AppControlAutoSyncViolationThreshold *int64                          `json:"appControlAutoSyncViolationThreshold,omitempty"`
	AppControlLastRefreshed              *SafeTime                       `json:"appControlLastRefreshed,omitempty"`
	AssetAvailability                    *string                         `json:"assetAvailability,omitempty"`
	ID                                   *string                         `json:"assetId,omitempty"`
	AssetInternetFacing                  *bool                           `json:"assetInternetFacing,omitempty"`
	AssetName                            string                          `json:"assetName"`
	AssetRisk                            *string                         `json:"assetRisk,omitempty"`
	AttackSurface                        *string                         `json:"attackSurface,omitempty"`
	AttackSurfacePendingChanges          *PendingChanges                 `json:"attackSurfacePendingChanges,omitempty"`
	BlastRadius                          *string                         `json:"blastRadius,omitempty"`
	BlastRadiusPendingChanges            *PendingChanges                 `json:"blastRadiusPendingChanges,omitempty"`
	BlockCustomIPs                       *string                         `json:"blockCustomIPs,omitempty"`
	BlockMaliciousIPs                    *string                         `json:"blockMaliciousIPs,omitempty"`
	BlockTemplatesAssigned               *int64                          `json:"blockTemplatesAssigned,omitempty"`
	BreachResponseLevel                  *string                         `json:"breachResponseLevel,omitempty"`
	BreachResponseModeSynced             *string                         `json:"breachResponseModeSynced,omitempty"`
	BusinessValue                        *string                         `json:"businessValue,omitempty"`
	CisaAdvisories                       *int64                          `json:"cisaAdvisories,omitempty"`
	CloudConnectorMode                   *string                         `json:"cloudConnectorMode,omitempty"`
	CloudTags                            []Tag                           `json:"cloudTags,omitempty"`
	ClusterIdentifier                    *string                         `json:"clusterIdentifier,omitempty"`
	ContainerNamespace                   *string                         `json:"containerNamespace,omitempty"`
	CoreTags                             map[string]string               `json:"coreTags,omitempty"`
	CPUCoreCount                         *int64                          `json:"cpuCoreCount,omitempty"`
	CPUName                              *string                         `json:"cpuName,omitempty"`
	CurrentTrafficConfiguration          *CurrentTrafficConfiguration    `json:"currentTrafficConfiguration,omitempty"`
	DeterministicID                      *string                         `json:"deterministicId,omitempty"`
	DiskCapacityInGB                     *int64                          `json:"diskCapacityInGB,omitempty"`
	FwCoexistenceCfgStatus               *string                         `json:"fwCoexistenceCfgStatus,omitempty"`
	FwConfigPendingChanges               *FWConfigPendingChanges         `json:"fwConfigPendingChanges,omitempty"`
	HasInaccessibleSegments              *bool                           `json:"hasInaccessibleSegments,omitempty"`
	HostName                             *string                         `json:"hostName,omitempty"`
	IamTemplatesAssigned                 *int64                          `json:"iamTemplatesAssigned,omitempty"`
	InboundAssetDeploymentState          *string                         `json:"inboundAssetDeploymentState,omitempty"`
	InboundAssetPolicyLastRefreshed      *SafeTime                       `json:"inboundAssetPolicyLastRefreshed,omitempty"`
	InboundAssetPolicyMode               *string                         `json:"inboundAssetPolicyMode,omitempty"`
	InboundAssetPolicyStatus             *string                         `json:"inboundAssetPolicyStatus,omitempty"`
	InboundAssetPolicyUpdatedAt          *SafeTime                       `json:"inboundAssetPolicyUpdatedAt,omitempty"`
	InboundAssetStatus                   *string                         `json:"inboundAssetStatus,omitempty"`
	InboundAutoSyncDeploymentMode        *string                         `json:"inboundAutoSyncDeploymentMode,omitempty"`
	InboundAutoSyncIncludeViolations     *bool                           `json:"inboundAutoSyncIncludeViolations,omitempty"`
	InboundAutoSyncIntervalMinutes       *int64                          `json:"inboundAutoSyncIntervalMinutes,omitempty"`
	InboundAutoSyncViolationThreshold    *int64                          `json:"inboundAutoSyncViolationThreshold,omitempty"`
	InboundInternetPaths                 *ReviewCoverage                 `json:"inboundInternetPaths,omitempty"`
	InboundInternetPorts                 *ReviewCoverage                 `json:"inboundInternetPorts,omitempty"`
	InboundIntranetPaths                 *ReviewCoverage                 `json:"inboundIntranetPaths,omitempty"`
	InboundIntranetPorts                 *ReviewCoverage                 `json:"inboundIntranetPorts,omitempty"`
	Interfaces                           []NetworkInterface              `json:"interfaces,omitempty"`
	IsFlowCollectorEdrType               *bool                           `json:"isFlowCollectorEdrType,omitempty"`
	KernelArchitecture                   *string                         `json:"kernelArchitecture,omitempty"`
	KernelVersion                        *string                         `json:"kernelVersion,omitempty"`
	LanInterfaceName                     *string                         `json:"lanInterfaceName,omitempty"`
	LastFWSynchronized                   *SafeTime                       `json:"lastFWSynchronized,omitempty"`
	LastPolicyDeploymentTriggeredAt      *SafeTime                       `json:"lastPolicyDeploymentTriggeredAt,omitempty"`
	LateralMovementAttacks               *int64                          `json:"lateralMovementAttacks,omitempty"`
	LateralMovementTechniques            *int64                          `json:"lateralMovementTechniques,omitempty"`
	LowestInboundAssetPolicyStatus       *string                         `json:"lowestInboundAssetPolicyStatus,omitempty"`
	LowestOutboundAssetPolicyStatus      *string                         `json:"lowestOutboundAssetPolicyStatus,omitempty"`
	ManagedBy                            *string                         `json:"managedBy,omitempty"`
	MicroDeploymentCompatible            *bool                           `json:"microDeploymentCompatible,omitempty"`
	MostRecentNewPath                    *SafeTime                       `json:"mostRecentNewPath,omitempty"`
	NamedNetworkChanges                  []MetadataNamedNetworkReference `json:"namedNetworkChanges,omitempty"`
	NamednetworksAssigned                *int64                          `json:"namednetworksAssigned,omitempty"`
	NewPathProcessingStopped             *bool                           `json:"newPathProcessingStopped,omitempty"`
	OsName                               *string                         `json:"osName,omitempty"`
	OutboundAssetDeploymentState         *string                         `json:"outboundAssetDeploymentState,omitempty"`
	OutboundAssetPolicyLastRefreshed     *SafeTime                       `json:"outboundAssetPolicyLastRefreshed,omitempty"`
	OutboundAssetPolicyMode              *string                         `json:"outboundAssetPolicyMode,omitempty"`
	OutboundAssetPolicyStatus            *string                         `json:"outboundAssetPolicyStatus,omitempty"`
	OutboundAssetPolicyUpdatedAt         *SafeTime                       `json:"outboundAssetPolicyUpdatedAt,omitempty"`
	OutboundAssetStatus                  *string                         `json:"outboundAssetStatus,omitempty"`
	OutboundAutoSyncDeploymentMode       *string                         `json:"outboundAutoSyncDeploymentMode,omitempty"`
	OutboundAutoSyncIncludeViolations    *bool                           `json:"outboundAutoSyncIncludeViolations,omitempty"`
	OutboundAutoSyncIntervalMinutes      *int64                          `json:"outboundAutoSyncIntervalMinutes,omitempty"`
	OutboundAutoSyncViolationThreshold   *int64                          `json:"outboundAutoSyncViolationThreshold,omitempty"`
	OutboundInternetPaths                *ReviewCoverage                 `json:"outboundInternetPaths,omitempty"`
	OutboundIntranetPaths                *ReviewCoverage                 `json:"outboundIntranetPaths,omitempty"`
	PendingAppControlChanges             *bool                           `json:"pendingAppControlChanges,omitempty"`
	PendingAttackSurfaceChanges          *bool                           `json:"pendingAttackSurfaceChanges,omitempty"`
	PendingBlastRadiusChanges            *bool                           `json:"pendingBlastRadiusChanges,omitempty"`
	PendingFWCoexistenceUpdateChanges    *bool                           `json:"pendingFWCoexistenceUpdateChanges,omitempty"`
	PendingFWConfigChanges               *bool                           `json:"pendingFWConfigChanges,omitempty"`
	Platform                             *string                         `json:"platform,omitempty"`
	PoliciesAssigned                     *int64                          `json:"policiesAssigned,omitempty"`
	PolicyStatus                         *string                         `json:"policyStatus,omitempty"`
	Programs                             []Program                       `json:"programs,omitempty"`
	RAMCapacityInMB                      *int64                          `json:"ramCapacityInMB,omitempty"`
	RuleSynchronizeStatus                *string                         `json:"ruleSynchronizeStatus,omitempty"`
	SecurityPatches                      *int64                          `json:"securityPatches,omitempty"`
	SerialNumber                         *string                         `json:"serialNumber,omitempty"`
	Tags                                 []Tag                           `json:"tags,omitempty"`
	TemplateChanges                      []TemplateReference             `json:"templateChanges,omitempty"`
	TemplatesAssigned                    *int64                          `json:"templatesAssigned,omitempty"`
	TotalBreachResponseComments          *int64                          `json:"totalBreachResponseComments,omitempty"`
	TotalComments                        *int64                          `json:"totalComments,omitempty"`
	TotalInboundComments                 *int64                          `json:"totalInboundComments,omitempty"`
	TotalOutboundComments                *int64                          `json:"totalOutboundComments,omitempty"`
	TotalPaths                           *int64                          `json:"totalPaths,omitempty"`
	TotalPorts                           *int64                          `json:"totalPorts,omitempty"`
	TotalPortsPathRestricted             *int64                          `json:"totalPortsPathRestricted,omitempty"`
	Type                                 string                          `json:"type"`
	UnreviewedPaths                      *int64                          `json:"unreviewedPaths,omitempty"`
	UnreviewedPorts                      *int64                          `json:"unreviewedPorts,omitempty"`
	UsergroupMostRecentNewPath           *SafeTime                       `json:"usergroupMostRecentNewPath,omitempty"`
	UsergroupOutboundInternetPaths       *ReviewCoverage                 `json:"usergroupOutboundInternetPaths,omitempty"`
	UsergroupOutboundIntranetPaths       *ReviewCoverage                 `json:"usergroupOutboundIntranetPaths,omitempty"`
	UsergroupTotalPaths                  *int64                          `json:"usergroupTotalPaths,omitempty"`
	UsergroupUnreviewedPaths             *int64                          `json:"usergroupUnreviewedPaths,omitempty"`
	Usergroups                           []AssetGroup                    `json:"usergroups,omitempty"`
	Users                                []AssetUser                     `json:"users,omitempty"`
	VendorInfo                           *string                         `json:"vendorInfo,omitempty"`
	VirtualizationSystem                 *string                         `json:"virtualizationSystem,omitempty"`
	Vulnerabilities                      *int64                          `json:"vulnerabilities,omitempty"`
}

func (o *AssetDetails) GetIPV6BlanketAllowStatus() *string {
	if o == nil {
		return nil
	}
	return o.IPV6BlanketAllowStatus
}

func (o *AssetDetails) GetActiveBreachModeTemplatesAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.ActiveBreachModeTemplatesAssigned
}

func (o *AssetDetails) GetAgentID() *string {
	if o == nil {
		return nil
	}
	return o.AgentID
}

func (o *AssetDetails) GetAgentLastCheckInTime() *SafeTime {
	if o == nil {
		return nil
	}
	return o.AgentLastCheckInTime
}

func (o *AssetDetails) GetAgentName() *string {
	if o == nil {
		return nil
	}
	return o.AgentName
}

func (o *AssetDetails) GetAgentStatus() *string {
	if o == nil {
		return nil
	}
	return o.AgentStatus
}

func (o *AssetDetails) GetAgentVersion() *string {
	if o == nil {
		return nil
	}
	return o.AgentVersion
}

func (o *AssetDetails) GetAllowTemplatesAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.AllowTemplatesAssigned
}

func (o *AssetDetails) GetAppControlAssetDeploymentState() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAssetDeploymentState
}

func (o *AssetDetails) GetAppControlAssetPendingChanges() *AppControlPendingChanges {
	if o == nil {
		return nil
	}
	return o.AppControlAssetPendingChanges
}

func (o *AssetDetails) GetAppControlAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAssetPolicyMode
}

func (o *AssetDetails) GetAppControlAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAssetPolicyStatus
}

func (o *AssetDetails) GetAppControlAssetPolicyUpdatedAt() *SafeTime {
	if o == nil {
		return nil
	}
	return o.AppControlAssetPolicyUpdatedAt
}

func (o *AssetDetails) GetAppControlAssetStatus() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAssetStatus
}

func (o *AssetDetails) GetAppControlAutoSyncDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncDeploymentMode
}

func (o *AssetDetails) GetAppControlAutoSyncIncludeViolations() *bool {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncIncludeViolations
}

func (o *AssetDetails) GetAppControlAutoSyncIntervalMinutes() *int64 {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncIntervalMinutes
}

func (o *AssetDetails) GetAppControlAutoSyncViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.AppControlAutoSyncViolationThreshold
}

func (o *AssetDetails) GetAppControlLastRefreshed() *SafeTime {
	if o == nil {
		return nil
	}
	return o.AppControlLastRefreshed
}

func (o *AssetDetails) GetAssetAvailability() *string {
	if o == nil {
		return nil
	}
	return o.AssetAvailability
}

func (o *AssetDetails) GetID() *string {
	if o == nil {
		return nil
	}
	return o.ID
}

func (o *AssetDetails) GetAssetInternetFacing() *bool {
	if o == nil {
		return nil
	}
	return o.AssetInternetFacing
}

func (o *AssetDetails) GetAssetName() string {
	if o == nil {
		return ""
	}
	return o.AssetName
}

func (o *AssetDetails) GetAssetRisk() *string {
	if o == nil {
		return nil
	}
	return o.AssetRisk
}

func (o *AssetDetails) GetAttackSurface() *string {
	if o == nil {
		return nil
	}
	return o.AttackSurface
}

func (o *AssetDetails) GetAttackSurfacePendingChanges() *PendingChanges {
	if o == nil {
		return nil
	}
	return o.AttackSurfacePendingChanges
}

func (o *AssetDetails) GetBlastRadius() *string {
	if o == nil {
		return nil
	}
	return o.BlastRadius
}

func (o *AssetDetails) GetBlastRadiusPendingChanges() *PendingChanges {
	if o == nil {
		return nil
	}
	return o.BlastRadiusPendingChanges
}

func (o *AssetDetails) GetBlockCustomIPs() *string {
	if o == nil {
		return nil
	}
	return o.BlockCustomIPs
}

func (o *AssetDetails) GetBlockMaliciousIPs() *string {
	if o == nil {
		return nil
	}
	return o.BlockMaliciousIPs
}

func (o *AssetDetails) GetBlockTemplatesAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.BlockTemplatesAssigned
}

func (o *AssetDetails) GetBreachResponseLevel() *string {
	if o == nil {
		return nil
	}
	return o.BreachResponseLevel
}

func (o *AssetDetails) GetBreachResponseModeSynced() *string {
	if o == nil {
		return nil
	}
	return o.BreachResponseModeSynced
}

func (o *AssetDetails) GetBusinessValue() *string {
	if o == nil {
		return nil
	}
	return o.BusinessValue
}

func (o *AssetDetails) GetCisaAdvisories() *int64 {
	if o == nil {
		return nil
	}
	return o.CisaAdvisories
}

func (o *AssetDetails) GetCloudConnectorMode() *string {
	if o == nil {
		return nil
	}
	return o.CloudConnectorMode
}

func (o *AssetDetails) GetCloudTags() []Tag {
	if o == nil {
		return nil
	}
	return o.CloudTags
}

func (o *AssetDetails) GetClusterIdentifier() *string {
	if o == nil {
		return nil
	}
	return o.ClusterIdentifier
}

func (o *AssetDetails) GetContainerNamespace() *string {
	if o == nil {
		return nil
	}
	return o.ContainerNamespace
}

func (o *AssetDetails) GetCoreTags() map[string]string {
	if o == nil {
		return nil
	}
	return o.CoreTags
}

func (o *AssetDetails) GetCPUCoreCount() *int64 {
	if o == nil {
		return nil
	}
	return o.CPUCoreCount
}

func (o *AssetDetails) GetCPUName() *string {
	if o == nil {
		return nil
	}
	return o.CPUName
}

func (o *AssetDetails) GetCurrentTrafficConfiguration() *CurrentTrafficConfiguration {
	if o == nil {
		return nil
	}
	return o.CurrentTrafficConfiguration
}

func (o *AssetDetails) GetDeterministicID() *string {
	if o == nil {
		return nil
	}
	return o.DeterministicID
}

func (o *AssetDetails) GetDiskCapacityInGB() *int64 {
	if o == nil {
		return nil
	}
	return o.DiskCapacityInGB
}

func (o *AssetDetails) GetFwCoexistenceCfgStatus() *string {
	if o == nil {
		return nil
	}
	return o.FwCoexistenceCfgStatus
}

func (o *AssetDetails) GetFwConfigPendingChanges() *FWConfigPendingChanges {
	if o == nil {
		return nil
	}
	return o.FwConfigPendingChanges
}

func (o *AssetDetails) GetHasInaccessibleSegments() *bool {
	if o == nil {
		return nil
	}
	return o.HasInaccessibleSegments
}

func (o *AssetDetails) GetHostName() *string {
	if o == nil {
		return nil
	}
	return o.HostName
}

func (o *AssetDetails) GetIamTemplatesAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.IamTemplatesAssigned
}

func (o *AssetDetails) GetInboundAssetDeploymentState() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetDeploymentState
}

func (o *AssetDetails) GetInboundAssetPolicyLastRefreshed() *SafeTime {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyLastRefreshed
}

func (o *AssetDetails) GetInboundAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyMode
}

func (o *AssetDetails) GetInboundAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyStatus
}

func (o *AssetDetails) GetInboundAssetPolicyUpdatedAt() *SafeTime {
	if o == nil {
		return nil
	}
	return o.InboundAssetPolicyUpdatedAt
}

func (o *AssetDetails) GetInboundAssetStatus() *string {
	if o == nil {
		return nil
	}
	return o.InboundAssetStatus
}

func (o *AssetDetails) GetInboundAutoSyncDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncDeploymentMode
}

func (o *AssetDetails) GetInboundAutoSyncIncludeViolations() *bool {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncIncludeViolations
}

func (o *AssetDetails) GetInboundAutoSyncIntervalMinutes() *int64 {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncIntervalMinutes
}

func (o *AssetDetails) GetInboundAutoSyncViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.InboundAutoSyncViolationThreshold
}

func (o *AssetDetails) GetInboundInternetPaths() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.InboundInternetPaths
}

func (o *AssetDetails) GetInboundInternetPorts() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.InboundInternetPorts
}

func (o *AssetDetails) GetInboundIntranetPaths() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.InboundIntranetPaths
}

func (o *AssetDetails) GetInboundIntranetPorts() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.InboundIntranetPorts
}

func (o *AssetDetails) GetInterfaces() []NetworkInterface {
	if o == nil {
		return nil
	}
	return o.Interfaces
}

func (o *AssetDetails) GetIsFlowCollectorEdrType() *bool {
	if o == nil {
		return nil
	}
	return o.IsFlowCollectorEdrType
}

func (o *AssetDetails) GetKernelArchitecture() *string {
	if o == nil {
		return nil
	}
	return o.KernelArchitecture
}

func (o *AssetDetails) GetKernelVersion() *string {
	if o == nil {
		return nil
	}
	return o.KernelVersion
}

func (o *AssetDetails) GetLanInterfaceName() *string {
	if o == nil {
		return nil
	}
	return o.LanInterfaceName
}

func (o *AssetDetails) GetLastFWSynchronized() *SafeTime {
	if o == nil {
		return nil
	}
	return o.LastFWSynchronized
}

func (o *AssetDetails) GetLastPolicyDeploymentTriggeredAt() *SafeTime {
	if o == nil {
		return nil
	}
	return o.LastPolicyDeploymentTriggeredAt
}

func (o *AssetDetails) GetLateralMovementAttacks() *int64 {
	if o == nil {
		return nil
	}
	return o.LateralMovementAttacks
}

func (o *AssetDetails) GetLateralMovementTechniques() *int64 {
	if o == nil {
		return nil
	}
	return o.LateralMovementTechniques
}

func (o *AssetDetails) GetLowestInboundAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.LowestInboundAssetPolicyStatus
}

func (o *AssetDetails) GetLowestOutboundAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.LowestOutboundAssetPolicyStatus
}

func (o *AssetDetails) GetManagedBy() *string {
	if o == nil {
		return nil
	}
	return o.ManagedBy
}

func (o *AssetDetails) GetMicroDeploymentCompatible() *bool {
	if o == nil {
		return nil
	}
	return o.MicroDeploymentCompatible
}

func (o *AssetDetails) GetMostRecentNewPath() *SafeTime {
	if o == nil {
		return nil
	}
	return o.MostRecentNewPath
}

func (o *AssetDetails) GetNamedNetworkChanges() []MetadataNamedNetworkReference {
	if o == nil {
		return nil
	}
	return o.NamedNetworkChanges
}

func (o *AssetDetails) GetNamednetworksAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.NamednetworksAssigned
}

func (o *AssetDetails) GetNewPathProcessingStopped() *bool {
	if o == nil {
		return nil
	}
	return o.NewPathProcessingStopped
}

func (o *AssetDetails) GetOsName() *string {
	if o == nil {
		return nil
	}
	return o.OsName
}

func (o *AssetDetails) GetOutboundAssetDeploymentState() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetDeploymentState
}

func (o *AssetDetails) GetOutboundAssetPolicyLastRefreshed() *SafeTime {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyLastRefreshed
}

func (o *AssetDetails) GetOutboundAssetPolicyMode() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyMode
}

func (o *AssetDetails) GetOutboundAssetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyStatus
}

func (o *AssetDetails) GetOutboundAssetPolicyUpdatedAt() *SafeTime {
	if o == nil {
		return nil
	}
	return o.OutboundAssetPolicyUpdatedAt
}

func (o *AssetDetails) GetOutboundAssetStatus() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAssetStatus
}

func (o *AssetDetails) GetOutboundAutoSyncDeploymentMode() *string {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncDeploymentMode
}

func (o *AssetDetails) GetOutboundAutoSyncIncludeViolations() *bool {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncIncludeViolations
}

func (o *AssetDetails) GetOutboundAutoSyncIntervalMinutes() *int64 {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncIntervalMinutes
}

func (o *AssetDetails) GetOutboundAutoSyncViolationThreshold() *int64 {
	if o == nil {
		return nil
	}
	return o.OutboundAutoSyncViolationThreshold
}

func (o *AssetDetails) GetOutboundInternetPaths() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.OutboundInternetPaths
}

func (o *AssetDetails) GetOutboundIntranetPaths() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.OutboundIntranetPaths
}

func (o *AssetDetails) GetPendingAppControlChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingAppControlChanges
}

func (o *AssetDetails) GetPendingAttackSurfaceChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingAttackSurfaceChanges
}

func (o *AssetDetails) GetPendingBlastRadiusChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingBlastRadiusChanges
}

func (o *AssetDetails) GetPendingFWCoexistenceUpdateChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingFWCoexistenceUpdateChanges
}

func (o *AssetDetails) GetPendingFWConfigChanges() *bool {
	if o == nil {
		return nil
	}
	return o.PendingFWConfigChanges
}

func (o *AssetDetails) GetPlatform() *string {
	if o == nil {
		return nil
	}
	return o.Platform
}

func (o *AssetDetails) GetPoliciesAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.PoliciesAssigned
}

func (o *AssetDetails) GetPolicyStatus() *string {
	if o == nil {
		return nil
	}
	return o.PolicyStatus
}

func (o *AssetDetails) GetPrograms() []Program {
	if o == nil {
		return nil
	}
	return o.Programs
}

func (o *AssetDetails) GetRAMCapacityInMB() *int64 {
	if o == nil {
		return nil
	}
	return o.RAMCapacityInMB
}

func (o *AssetDetails) GetRuleSynchronizeStatus() *string {
	if o == nil {
		return nil
	}
	return o.RuleSynchronizeStatus
}

func (o *AssetDetails) GetSecurityPatches() *int64 {
	if o == nil {
		return nil
	}
	return o.SecurityPatches
}

func (o *AssetDetails) GetSerialNumber() *string {
	if o == nil {
		return nil
	}
	return o.SerialNumber
}

func (o *AssetDetails) GetTags() []Tag {
	if o == nil {
		return nil
	}
	return o.Tags
}

func (o *AssetDetails) GetTemplateChanges() []TemplateReference {
	if o == nil {
		return nil
	}
	return o.TemplateChanges
}

func (o *AssetDetails) GetTemplatesAssigned() *int64 {
	if o == nil {
		return nil
	}
	return o.TemplatesAssigned
}

func (o *AssetDetails) GetTotalBreachResponseComments() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalBreachResponseComments
}

func (o *AssetDetails) GetTotalComments() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalComments
}

func (o *AssetDetails) GetTotalInboundComments() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalInboundComments
}

func (o *AssetDetails) GetTotalOutboundComments() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalOutboundComments
}

func (o *AssetDetails) GetTotalPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalPaths
}

func (o *AssetDetails) GetTotalPorts() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalPorts
}

func (o *AssetDetails) GetTotalPortsPathRestricted() *int64 {
	if o == nil {
		return nil
	}
	return o.TotalPortsPathRestricted
}

func (o *AssetDetails) GetType() string {
	if o == nil {
		return ""
	}
	return o.Type
}

func (o *AssetDetails) GetUnreviewedPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.UnreviewedPaths
}

func (o *AssetDetails) GetUnreviewedPorts() *int64 {
	if o == nil {
		return nil
	}
	return o.UnreviewedPorts
}

func (o *AssetDetails) GetUsergroupMostRecentNewPath() *SafeTime {
	if o == nil {
		return nil
	}
	return o.UsergroupMostRecentNewPath
}

func (o *AssetDetails) GetUsergroupOutboundInternetPaths() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.UsergroupOutboundInternetPaths
}

func (o *AssetDetails) GetUsergroupOutboundIntranetPaths() *ReviewCoverage {
	if o == nil {
		return nil
	}
	return o.UsergroupOutboundIntranetPaths
}

func (o *AssetDetails) GetUsergroupTotalPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.UsergroupTotalPaths
}

func (o *AssetDetails) GetUsergroupUnreviewedPaths() *int64 {
	if o == nil {
		return nil
	}
	return o.UsergroupUnreviewedPaths
}

func (o *AssetDetails) GetUsergroups() []AssetGroup {
	if o == nil {
		return nil
	}
	return o.Usergroups
}

func (o *AssetDetails) GetUsers() []AssetUser {
	if o == nil {
		return nil
	}
	return o.Users
}

func (o *AssetDetails) GetVendorInfo() *string {
	if o == nil {
		return nil
	}
	return o.VendorInfo
}

func (o *AssetDetails) GetVirtualizationSystem() *string {
	if o == nil {
		return nil
	}
	return o.VirtualizationSystem
}

func (o *AssetDetails) GetVulnerabilities() *int64 {
	if o == nil {
		return nil
	}
	return o.Vulnerabilities
}

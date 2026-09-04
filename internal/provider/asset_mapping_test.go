package provider

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

// A trimmed but field-accurate GET /api/assets/{assetId} body. Every key here is
// one the asset service actually emits.
const assetDetailsJSON = `{
  "assetId": "a1b2c3d4-0000-0000-0000-000000000000",
  "assetName": "payroll-db-01",
  "type": "server",
  "coreTags": {"application": "payroll", "environment": "prod"},

  "attackSurface": "high",
  "blastRadius": "medium",
  "assetRisk": "high",

  "inboundAssetDeploymentState": "enabled",
  "outboundAssetDeploymentState": "disabled",
  "inboundAssetPolicyMode": "under-test",
  "outboundAssetPolicyMode": "not-deployed",
  "inboundAssetStatus": "secure-test",
  "outboundAssetStatus": "unsecured",
  "inboundAssetPolicyStatus": "allow-open-ports",
  "lowestInboundAssetPolicyStatus": "zerotrust",
  "lowestOutboundAssetPolicyStatus": "default-allow",
  "inboundAssetPolicyUpdatedAt": "2026-08-30T11:22:33Z",
  "lastPolicyDeploymentTriggeredAt": "2026-08-30T10:00:00Z",
  "microDeploymentCompatible": true,
  "policyStatus": "pending",

  "pendingAttackSurfaceChanges": true,
  "attackSurfacePendingChanges": {
    "allowTemplates": ["payroll-web"],
    "assetPolicySyncPending": true,
    "internetPorts": 2,
    "intranetPorts": 5,
    "peerChange": false
  },
  "pendingFWConfigChanges": true,
  "fwConfigPendingChanges": {
    "fwCoexistenceCfgUpdatePending": true,
    "intranetChange": false,
    "IPV6BlanketAllow": true
  },
  "appControlAssetPendingChanges": {
    "allowTemplates": ["office"],
    "changedApplications": 3
  },

  "programs": [{"name": "postgres", "path": "/usr/bin/postgres", "image": ""}],
  "interfaces": [{"name": "eth0", "ipaddresses": ["10.0.0.5"], "macaddress": "00:11:22:33:44:55", "flags": ["up"]}],
  "tags": [{"id": "t1", "key": "application", "value": "payroll", "isCloudTag": false}],
  "templateChanges": [{"templateId": "tpl-1", "templateName": "payroll-web"}],
  "namedNetworkChanges": [{"namedNetworkId": "nn-1", "namedNetworkName": "corp"}],
  "inboundInternetPorts": {"total": 10, "reviewed": 7, "unreviewed": 3, "allowed": 5, "allowedPorts": 5},

  "currentTrafficConfiguration": "enable-all",
  "totalPorts": 10,
  "unreviewedPorts": 3
}`

func decodeAssetDetails(t *testing.T) *shared.AssetDetails {
	t.Helper()
	var details shared.AssetDetails
	if err := json.Unmarshal([]byte(assetDetailsJSON), &details); err != nil {
		t.Fatalf("decoding AssetDetails: %v", err)
	}
	return &details
}

func TestAssetDataSourceRefreshPopulatesEnforcementState(t *testing.T) {
	t.Parallel()
	var model AssetDataSourceModel
	model.RefreshFromSharedAssetDetails(decodeAssetDetails(t))

	// These are the fields that decide whether policy is actually in force.
	// They were once declared but never populated, so every asset reported null
	// and read as "not enforced". They live on the data source now, because the
	// backend moves them with no Terraform action behind it.
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"inbound_asset_deployment_state", model.InboundAssetDeploymentState.ValueString(), "enabled"},
		{"outbound_asset_deployment_state", model.OutboundAssetDeploymentState.ValueString(), "disabled"},
		{"inbound_asset_policy_mode", model.InboundAssetPolicyMode.ValueString(), "under-test"},
		{"outbound_asset_policy_mode", model.OutboundAssetPolicyMode.ValueString(), "not-deployed"},
		{"inbound_asset_status", model.InboundAssetStatus.ValueString(), "secure-test"},
		{"inbound_asset_policy_status", model.InboundAssetPolicyStatus.ValueString(), "allow-open-ports"},
		{"lowest_inbound_asset_policy_status", model.LowestInboundAssetPolicyStatus.ValueString(), "zerotrust"},
		{"policy_status", model.PolicyStatus.ValueString(), "pending"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}

	if !model.MicroDeploymentCompatible.ValueBool() {
		t.Error("micro_deployment_compatible = false, want true; it gates per-port deploys")
	}
	if got := model.LastPolicyDeploymentTriggeredAt.ValueString(); got != "2026-08-30T10:00:00Z" {
		t.Errorf("last_policy_deployment_triggered_at = %q", got)
	}
}

func TestAssetDataSourceRefreshKeepsRiskScoresDistinctFromEnforcement(t *testing.T) {
	t.Parallel()
	var model AssetDataSourceModel
	model.RefreshFromSharedAssetDetails(decodeAssetDetails(t))

	// attackSurface and blastRadius are risk scores, not enforcement states.
	// Reading them as enforcement is the easiest mistake to make against this API.
	if got := model.AttackSurface.ValueString(); got != "high" {
		t.Errorf("attack_surface = %q, want the risk score \"high\"", got)
	}
	if got := model.BlastRadius.ValueString(); got != "medium" {
		t.Errorf("blast_radius = %q, want the risk score \"medium\"", got)
	}
	if model.AttackSurface.ValueString() == model.InboundAssetDeploymentState.ValueString() {
		t.Error("attack_surface and inbound_asset_deployment_state must not be the same value")
	}
}

func TestAssetDataSourceRefreshPopulatesPendingChanges(t *testing.T) {
	t.Parallel()
	var model AssetDataSourceModel
	model.RefreshFromSharedAssetDetails(decodeAssetDetails(t))

	if !model.PendingAttackSurfaceChanges.ValueBool() {
		t.Error("pending_attack_surface_changes = false, want true")
	}
	pc := model.AttackSurfacePendingChanges
	if pc == nil {
		t.Fatal("attack_surface_pending_changes is nil")
	}
	// assetPolicySyncPending replaced the old progressiveSyncPending field.
	if !pc.AssetPolicySyncPending.ValueBool() {
		t.Error("asset_policy_sync_pending = false, want true")
	}
	if got := pc.InternetPorts.ValueInt64(); got != 2 {
		t.Errorf("internet_ports = %d, want 2", got)
	}
	if len(pc.AllowTemplates) != 1 || pc.AllowTemplates[0].ValueString() != "payroll-web" {
		t.Errorf("allow_templates = %v", pc.AllowTemplates)
	}

	fw := model.FwConfigPendingChanges
	if fw == nil {
		t.Fatal("fw_config_pending_changes is nil")
	}
	if !fw.FwCoexistenceCfgUpdatePending.ValueBool() || !fw.IPV6BlanketAllow.ValueBool() {
		t.Errorf("fw_config_pending_changes = %+v", fw)
	}

	ac := model.AppControlAssetPendingChanges
	if ac == nil {
		t.Fatal("app_control_asset_pending_changes is nil")
	}
	if got := ac.ChangedApplications.ValueInt64(); got != 3 {
		t.Errorf("changed_applications = %d, want 3", got)
	}
}

func TestAssetDataSourceRefreshPopulatesNestedCollections(t *testing.T) {
	t.Parallel()
	var model AssetDataSourceModel
	model.RefreshFromSharedAssetDetails(decodeAssetDetails(t))

	if len(model.Programs) != 1 || model.Programs[0].Name.ValueString() != "postgres" {
		t.Errorf("programs = %v", model.Programs)
	}
	if len(model.Interfaces) != 1 || model.Interfaces[0].Name.ValueString() != "eth0" {
		t.Errorf("interfaces = %v", model.Interfaces)
	}
	if len(model.Tags) != 1 || model.Tags[0].Key.ValueString() != "application" {
		t.Errorf("tags = %v", model.Tags)
	}
	if len(model.TemplateChanges) != 1 || model.TemplateChanges[0].TemplateName.ValueString() != "payroll-web" {
		t.Errorf("template_changes = %v", model.TemplateChanges)
	}
	if got := model.CoreTags["application"].ValueString(); got != "payroll" {
		t.Errorf("core_tags[application] = %q", got)
	}
	if model.InboundInternetPorts == nil || model.InboundInternetPorts.Unreviewed.ValueInt64() != 3 {
		t.Errorf("inbound_internet_ports = %+v", model.InboundInternetPorts)
	}
	if got := model.CurrentTrafficConfiguration.ValueString(); got != "enable-all" {
		t.Errorf("current_traffic_configuration = %q", got)
	}
}

// The asset resource is import-only: Create is refused and Update sends just the
// managed fields. Anything else in AssetDetails moves without a Terraform action,
// so it belongs on the data source, where reading it costs no state and reports no
// drift. This pins that split, because the schema is generated and a change to
// RESOURCE_FIELDS in scripts/gen_asset_provider.py would otherwise widen the
// resource silently.
func TestAssetResourceHoldsOnlyTheManagedSurface(t *testing.T) {
	t.Parallel()

	want := []string{
		"agent_id",             // sent in the update body
		"asset_name",           // practitioner-set
		"core_tags",            // practitioner-set
		"deterministic_id",     // sent in the update body
		"id",                   // identity
		"inbound_enforcement",  // deployment toggle
		"outbound_enforcement", // deployment toggle
		"type",                 // practitioner-set
		"vendor_info",          // sent in the update body
	}

	got := tfsdkFieldNames(reflect.TypeOf(AssetResourceModel{}))
	if !slices.Equal(got, want) {
		t.Errorf("asset resource attributes:\n got %v\nwant %v", got, want)
	}

	// Everything the resource dropped must still be readable somewhere.
	ds := tfsdkFieldNames(reflect.TypeOf(AssetDataSourceModel{}))
	for _, name := range []string{
		"policy_status", "vulnerabilities", "total_ports", "agent_last_check_in_time",
		"inbound_asset_deployment_state", "micro_deployment_compatible", "tags",
	} {
		if !slices.Contains(ds, name) {
			t.Errorf("%q is on neither the resource nor the data source", name)
		}
	}
	if len(ds) <= len(want) {
		t.Errorf("data source exposes %d attributes, expected far more than the resource's %d",
			len(ds), len(want))
	}
}

func tfsdkFieldNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		if tag, ok := t.Field(i).Tag.Lookup("tfsdk"); ok {
			names = append(names, tag)
		}
	}
	slices.Sort(names)
	return names
}

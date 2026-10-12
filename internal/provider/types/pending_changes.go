package types

import "github.com/hashicorp/terraform-plugin-framework/types"

type PendingChanges struct {
	AllowTemplates           []types.String `tfsdk:"allow_templates"`
	AssetPolicySyncPending   types.Bool     `tfsdk:"asset_policy_sync_pending"`
	BlockTemplates           []types.String `tfsdk:"block_templates"`
	InternetPaths            types.Int64    `tfsdk:"internet_paths"`
	InternetPorts            types.Int64    `tfsdk:"internet_ports"`
	IntranetPaths            types.Int64    `tfsdk:"intranet_paths"`
	IntranetPorts            types.Int64    `tfsdk:"intranet_ports"`
	NamednetworkChange       []types.String `tfsdk:"namednetwork_change"`
	PeerChange               types.Bool     `tfsdk:"peer_change"`
	UnassignedAllowTemplates []types.String `tfsdk:"unassigned_allow_templates"`
	UnassignedBlockTemplates []types.String `tfsdk:"unassigned_block_templates"`
}

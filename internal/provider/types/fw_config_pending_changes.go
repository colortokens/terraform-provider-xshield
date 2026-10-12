package types

import "github.com/hashicorp/terraform-plugin-framework/types"

type FWConfigPendingChanges struct {
	FwCoexistenceCfgUpdatePending types.Bool `tfsdk:"fw_coexistence_cfg_update_pending"`
	IntranetChange                types.Bool `tfsdk:"intranet_change"`
	IPV6BlanketAllow              types.Bool `tfsdk:"ipv6_blanket_allow"`
}

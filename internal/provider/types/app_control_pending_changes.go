package types

import "github.com/hashicorp/terraform-plugin-framework/types"

type AppControlPendingChanges struct {
	AllowTemplates      []types.String `tfsdk:"allow_templates"`
	BlockTemplates      []types.String `tfsdk:"block_templates"`
	ChangedApplications types.Int64    `tfsdk:"changed_applications"`
}

# The azure enforcement module sends this for you. Written by hand, it must list
# the ID of every resource the snapshot asks for, and reference them, so it is
# sent only once they all exist.
resource "xshield_azure_enforcement_receipt" "this" {
  cloud_account_id = data.xshield_azure_enforcement_snapshot.this.cloud_account_id
  region           = data.xshield_azure_enforcement_snapshot.this.region
  workspace        = "xshield-enforcement-eastus2"
  snapshot_version = data.xshield_azure_enforcement_snapshot.this.version

  network_security_groups = { for key, group in azurerm_network_security_group.this : key => group.id }
  subnet_associations     = { for key, association in azurerm_subnet_network_security_group_association.this : key => association.id }
  interface_associations  = { for key, association in azurerm_network_interface_security_group_association.this : key => association.id }
  # Changes whenever the apply recreates a group or association, which Azure gives its old ID.
  resend_trigger = join(",", [for key in sort(keys(terraform_data.applied)) : terraform_data.applied[key].id])
}

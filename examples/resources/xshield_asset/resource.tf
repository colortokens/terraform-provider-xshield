# Assets cannot be created through Terraform. Import an existing asset, then
# manage it.
#
#   terraform import xshield_asset.my_asset "web-server-01"

resource "xshield_asset" "my_asset" {
  asset_name = "web-server-01"
  type       = "server"

  core_tags = {
    application = "payroll"
    environment = "prod"
  }

  # Enforcement is what makes deployed policy take effect. Leave either unset to
  # leave that direction as it is.
  inbound_enforcement  = true
  outbound_enforcement = false
}

# The resource holds only what Terraform manages. Everything the agent reports
# and the backend derives is read through the data source, so a heartbeat or a
# risk rescore never shows up as drift on this resource.
data "xshield_asset" "my_asset" {
  id = xshield_asset.my_asset.id
}

# attack_surface and blast_radius are risk scores, not enforcement state. The
# fields that describe enforcement are these.
output "enforcement" {
  value = {
    inbound_state  = data.xshield_asset.my_asset.inbound_asset_deployment_state
    inbound_mode   = data.xshield_asset.my_asset.inbound_asset_policy_mode
    inbound_status = data.xshield_asset.my_asset.inbound_asset_status
    pending        = data.xshield_asset.my_asset.pending_attack_surface_changes
  }
}

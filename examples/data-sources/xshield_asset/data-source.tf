# Look an asset up by name, so nothing here depends on knowing a UUID from the
# portal. Set id instead when you already have it; setting both is an error.
data "xshield_asset" "my_asset" {
  asset_name = "web-server-01"
}

# Everything the platform knows about the asset is on the data source, including
# the state that moves on its own and so is deliberately absent from the resource.
output "posture" {
  value = {
    policy_status  = data.xshield_asset.my_asset.policy_status
    inbound_state  = data.xshield_asset.my_asset.inbound_asset_deployment_state
    open_ports     = data.xshield_asset.my_asset.total_ports
    unreviewed     = data.xshield_asset.my_asset.unreviewed_ports
    last_check_in  = data.xshield_asset.my_asset.agent_last_check_in_time
    micro_deployed = data.xshield_asset.my_asset.micro_deployment_compatible
  }
}

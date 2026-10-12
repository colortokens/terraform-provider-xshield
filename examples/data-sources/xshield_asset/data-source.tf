# Look up by name, so nothing here depends on knowing a UUID up front.
data "xshield_asset" "by_name" {
  asset_name = "web-server-01"
}

# Or by id, when you already have it. Setting both is an error.
data "xshield_asset" "by_id" {
  id = "12345678-1234-1234-1234-123456789012"
}

# Everything the platform knows about the asset is on the data source, including
# the state that moves on its own and so is deliberately absent from the resource.
output "posture" {
  value = {
    policy_status  = data.xshield_asset.by_name.policy_status
    inbound_state  = data.xshield_asset.by_name.inbound_asset_deployment_state
    open_ports     = data.xshield_asset.by_name.total_ports
    unreviewed     = data.xshield_asset.by_name.unreviewed_ports
    last_check_in  = data.xshield_asset.by_name.agent_last_check_in_time
    micro_deployed = data.xshield_asset.by_name.micro_deployment_compatible
  }
}

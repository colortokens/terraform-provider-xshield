# Every production payroll asset, with its enforcement state.
data "xshield_assets" "payroll" {
  criteria = "application = 'payroll' AND environment = 'prod'"
}

# Assets that cannot take a per-port deployment, which a deployment plan must avoid.
output "whole_asset_only" {
  value = [
    for a in data.xshield_assets.payroll.assets : a.asset_name
    if !a.micro_deployment_compatible
  ]
}

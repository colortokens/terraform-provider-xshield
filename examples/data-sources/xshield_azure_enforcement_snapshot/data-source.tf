# Most configurations use this through the azure enforcement module, which
# creates every resource it lists. Reading it directly is useful for review:
# what would the next apply hold, and where does each workload's group go?
# Without enforcement_plan, which only the module sets, such a read does not
# count as the pipeline's plan, so it cannot hide a pipeline that has stopped.
data "xshield_azure_enforcement_snapshot" "this" {
  cloud_account_id = "00000000-0000-0000-0000-000000000000"
  region           = "eastus2"
}

output "groups" {
  value = sort(keys(data.xshield_azure_enforcement_snapshot.this.network_security_groups))
}

output "where_each_asset_is_enforced" {
  value = { for id, asset in data.xshield_azure_enforcement_snapshot.this.assets : id => asset.level }
}

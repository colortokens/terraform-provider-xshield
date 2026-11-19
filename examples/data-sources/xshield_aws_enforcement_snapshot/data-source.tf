# Most configurations use this through the aws enforcement module, which
# creates every resource it lists. Reading it directly is useful for review:
# what would the next apply hold, and for which workloads? Without
# enforcement_plan, which only the module sets, such a read does not count as
# the pipeline's plan, so it cannot hide a pipeline that has stopped.
data "xshield_aws_enforcement_snapshot" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

output "workloads" {
  value = sort(keys(data.xshield_aws_enforcement_snapshot.this.security_groups))
}

output "rules_for_orders_db" {
  value = [for key, rule in data.xshield_aws_enforcement_snapshot.this.ingress_rules : key if rule.security_group == "rds/orders-db"]
}

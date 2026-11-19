# Xshield names the resources that carry the group, that it does not enforce on, and that nobody acknowledged when the
# change was approved, such as a load balancer attached since. Each loses what Xshield takes out of the group.

locals {
  unacknowledged_carriers = local.changed ? data.xshield_aws_security_group_rules.this[0].unacknowledged_carriers : []
  unacknowledged_carriers_message = length(local.unacknowledged_carriers) == 0 ? "" : format(
    "Security group %s is also carried by %s, which Xshield does not enforce on and nobody acknowledged when the change was approved. They will lose the rules this apply takes out of the group. Deploy the change again in Xshield to review and acknowledge them, or give each its own security group first.",
    var.group_name, join(", ", local.unacknowledged_carriers),
  )
}

check "unacknowledged_carriers" {
  assert {
    condition     = length(local.unacknowledged_carriers) == 0
    error_message = local.unacknowledged_carriers_message
  }
}

output "unacknowledged_carriers" {
  description = "Resources that carry the group, that Xshield does not enforce on, and that nobody acknowledged when the change was approved. Each loses the rules Xshield takes out of the group. Empty when no approved change applies to the group."
  value       = tolist(local.unacknowledged_carriers)
}

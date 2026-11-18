# Returns the Xshield security group a database, function or service must
# attach, from the handle its own workspace already knows. Reads the SSM
# parameter the enforcement workspace writes; needs no Xshield credentials.

# Reads the handle's own path rather than one parameter, so a resource Xshield
# lists no entry for, as in an account with nothing published, gets no group
# instead of a failed plan.
data "aws_ssm_parameters_by_path" "entry" {
  path            = "${var.directory_prefix}/${local.handle}"
  with_decryption = false

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z0-9-]+/[A-Za-z0-9_.-]+$", local.handle))
      error_message = "handle must be <kind>/<name>, such as rds/orders-db, rds-cluster/orders, lambda/orders-api, flink/clickstream, apprunner/orders-web or asg/orders-web."
    }
  }
}

locals {
  # RDS stores identifiers in lowercase, so Xshield's handle for one is lowercase.
  handle         = startswith(var.handle, "rds/") || startswith(var.handle, "rds-cluster/") ? lower(var.handle) : var.handle
  parameter_name = "${var.directory_prefix}/${local.handle}/security-groups"
  found          = contains(data.aws_ssm_parameters_by_path.entry.names, local.parameter_name)
  entry = jsondecode(local.found
    ? nonsensitive(data.aws_ssm_parameters_by_path.entry.values[index(data.aws_ssm_parameters_by_path.entry.names, local.parameter_name)])
    : jsonencode({ handle = local.handle, security_group_ids = [] })
  )
  slot_limit = try(local.entry.slot_limit, null)

  # Only the groups in the resource's VPC; an entry written before the enforcement module kept
  # groups by VPC gives all of them.
  by_vpc             = try(local.entry.security_group_ids_by_vpc, null)
  security_group_ids = try(local.by_vpc[var.vpc_id], [for id in local.entry.security_group_ids : id if local.by_vpc == null])
  other_vpcs         = local.by_vpc == null ? [] : sort([for vpc, ids in local.by_vpc : vpc if vpc != var.vpc_id && length(ids) > 0])
}

# A resource moved to another VPC gets no group of Xshield's until Xshield has discovered it
# there and the enforcement workspace has created its group in that VPC.
check "group_in_vpc" {
  assert {
    condition     = length(local.other_vpcs) == 0 || length(local.security_group_ids) > 0
    error_message = "Xshield's group for ${local.handle} is in ${join(", ", local.other_vpcs)}, not ${var.vpc_id}, so the resource gets none of Xshield's groups. This is expected on the run that moves it to ${var.vpc_id}: once Xshield has discovered it there and the enforcement workspace has applied, the next apply here attaches its group in ${var.vpc_id}. Otherwise, check that vpc_id is the VPC the resource is in."
  }
}

# Warns rather than fails when asked to: a resource the same plan creates has no
# entry until Xshield discovers it, and its plan must still go ahead.
check "directory_entry" {
  assert {
    condition     = local.found || !var.warn_when_unlisted
    error_message = "Xshield lists no entry for ${local.handle} at ${local.parameter_name}. This is expected on the run that creates the resource, until Xshield has discovered it and the enforcement workspace has applied, and while Xshield's policy gives the resource nothing to attach. Otherwise, compare the handle with the enforcement module's directory_entries output, and look for the resource among the assetRefused and groupRefused notices of the xshield_enforcement_status data source."
  }
}

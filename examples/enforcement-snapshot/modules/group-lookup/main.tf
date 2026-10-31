# Returns the Xshield security group a database, function or service must
# attach, from the handle its own workspace already knows. Reads the SSM
# parameter the enforcement workspace writes; needs no Xshield credentials.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "handle" {
  description = "The resource's kind and name: rds/<DB instance identifier>, rds-cluster/<cluster identifier>, lambda/<function name>, flink/<application name>, apprunner/<service name> or asg/<Auto Scaling group name>. An RDS identifier may be given in any case."
  type        = string
}

variable "directory_prefix" {
  description = "SSM path the enforcement workspace writes the directory under."
  type        = string
  default     = "/colortokens/v1"
}

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
}

# Warns rather than fails: a resource the same plan creates has no entry until
# Xshield discovers it, and its plan must still go ahead.
check "directory_entry" {
  assert {
    condition     = local.found
    error_message = "Xshield lists no entry for ${local.handle} at ${local.parameter_name}. This is expected on the run that creates the resource, until Xshield has discovered it and the enforcement workspace has applied, and while Xshield's policy gives the resource nothing to attach. Otherwise, compare the handle with the enforcement module's directory output, and look for the resource among the assetRefused and groupRefused notices of the xshield_enforcement_status data source."
  }
}

output "security_group_ids" {
  description = "Security group IDs to add to the resource's own list. Empty while Xshield lists no entry for the resource."
  value       = local.entry.security_group_ids

  precondition {
    condition     = local.entry.handle == local.handle
    error_message = "The directory entry at ${local.parameter_name} is for ${local.entry.handle}, not ${local.handle}. Only the enforcement workspace should write under ${var.directory_prefix}."
  }
}

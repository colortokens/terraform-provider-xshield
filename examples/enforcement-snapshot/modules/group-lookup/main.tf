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
  description = "The resource's kind and name: rds/<DB instance identifier>, rds-cluster/<cluster identifier>, lambda/<function name>, flink/<application name> or apprunner/<service name>."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+/[A-Za-z0-9_.-]+$", var.handle))
    error_message = "handle must be <kind>/<name>, such as rds/orders-db, rds-cluster/orders, lambda/orders-api, flink/clickstream or apprunner/orders-web."
  }
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
  path            = "${var.directory_prefix}/${var.handle}"
  with_decryption = false
}

locals {
  parameter_name = "${var.directory_prefix}/${var.handle}/security-groups"
  found          = contains(data.aws_ssm_parameters_by_path.entry.names, local.parameter_name)
  entry = jsondecode(local.found
    ? nonsensitive(data.aws_ssm_parameters_by_path.entry.values[index(data.aws_ssm_parameters_by_path.entry.names, local.parameter_name)])
    : jsonencode({ handle = var.handle, security_group_ids = [] })
  )
}

output "security_group_ids" {
  description = "Security group IDs to add to the resource's own list. Empty while Xshield has no rule for it, or no entry at all."
  value       = local.entry.security_group_ids

  precondition {
    condition     = local.entry.handle == var.handle
    error_message = "The directory entry at ${local.parameter_name} is for ${local.entry.handle}, not ${var.handle}. Only the enforcement workspace should write under ${var.directory_prefix}."
  }
}

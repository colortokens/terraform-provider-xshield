# Declares one of your own security group's rules through Xshield Full control. Every rule comes back as
# declared until an approved change narrows one, which then leaves once every workload that still needs it
# carries its ct-cohort- group. A group no change applies to never reads its rules from Xshield, so its plan
# shows nothing from Xshield, and its VPC and rules may be values the plan learns only at apply.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

variable "xshield_changes" {
  description = "The account and region's xshield_aws_security_group_changes data source, read once in the root module and passed to every group's module."
  type = object({
    cloud_account_id = string
    region           = string
    groups           = map(set(string))
  })
}

variable "vpc_id" {
  description = "The group's VPC. It may be a VPC the same configuration creates."
  type        = string
}

variable "group_name" {
  description = "The group's name, as the group's own resource sets it."
  type        = string
}

variable "security_group_id" {
  description = "The group the rules belong to. It may be a group the same configuration creates."
  type        = string
}

variable "ingress" {
  description = "Ingress rules keyed by a stable name, with the arguments of aws_vpc_security_group_ingress_rule."
  type = map(object({
    ip_protocol                  = string
    from_port                    = optional(number)
    to_port                      = optional(number)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
    description                  = optional(string)
    tags                         = optional(map(string))
  }))
  default = {}
}

variable "egress" {
  description = "Egress rules keyed by a stable name, with the arguments of aws_vpc_security_group_egress_rule."
  type = map(object({
    ip_protocol                  = string
    from_port                    = optional(number)
    to_port                      = optional(number)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
    description                  = optional(string)
    tags                         = optional(map(string))
  }))
  default = {}
}

locals {
  vpcs_with_a_change = lookup(var.xshield_changes.groups, var.group_name, [])
  # The VPC is compared only when a group with this name has a change, so a VPC the plan creates stays unknown.
  changed = length(local.vpcs_with_a_change) > 0 ? contains(local.vpcs_with_a_change, var.vpc_id) : false
}

data "xshield_aws_security_group_rules" "this" {
  count = local.changed ? 1 : 0

  cloud_account_id = var.xshield_changes.cloud_account_id
  region           = var.xshield_changes.region
  vpc_id           = var.vpc_id
  group_name       = var.group_name

  ingress = var.ingress
  egress  = var.egress
}

locals {
  ingress = local.changed ? data.xshield_aws_security_group_rules.this[0].ingress_rules : var.ingress
  egress  = local.changed ? data.xshield_aws_security_group_rules.this[0].egress_rules : var.egress
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.ingress

  security_group_id            = var.security_group_id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  referenced_security_group_id = each.value.referenced_security_group_id
  description                  = each.value.description
  tags                         = each.value.tags
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.egress

  security_group_id            = var.security_group_id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  referenced_security_group_id = each.value.referenced_security_group_id
  description                  = each.value.description
  tags                         = each.value.tags
}

output "changed" {
  description = "Whether an approved Full control change applies to the group."
  value       = local.changed
}

output "revoked" {
  description = "Declared rules Xshield has left out, as ingress/<key> or egress/<key>."
  value       = local.changed ? data.xshield_aws_security_group_rules.this[0].revoked : []
}

output "pending" {
  description = "Declared rules an approved change will leave out once every workload that keeps them carries its cohort."
  value       = local.changed ? data.xshield_aws_security_group_rules.this[0].pending : []
}

output "ingress_keys" {
  description = "Keys of the ingress rules declared now; adopt existing rules only under these, so a revoked rule's import never outlives it."
  value       = keys(local.ingress)
}

output "egress_keys" {
  description = "Keys of the egress rules declared now; adopt existing rules only under these."
  value       = keys(local.egress)
}

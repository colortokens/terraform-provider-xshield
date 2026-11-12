# Declares one of your own security group's rules through Xshield Full control. Every rule comes back as
# declared until an approved change narrows one, which then leaves once every workload that still needs it
# carries its ct-cohort- group. A group no change applies to never reads its rules from Xshield, so its plan
# shows nothing from Xshield beyond the record kept in state, and its VPC and rules may be values the plan learns
# only at apply. Its name may be too, while no change is published for the account and region at all.

locals {
  # With no change published for the account and region no name can match one, so a name the plan learns only
  # at apply, as name_prefix gives a group on the run that creates it, is never looked up.
  vpcs_with_a_change = length(var.xshield_changes.groups) == 0 ? [] : lookup(var.xshield_changes.groups, var.group_name, [])
  # The VPC is compared only when a group with this name has a change, so a VPC the plan creates stays unknown.
  changed = length(local.vpcs_with_a_change) > 0 ? contains(local.vpcs_with_a_change, var.vpc_id) : false
}

data "xshield_aws_security_group_rules" "this" {
  count = local.changed ? 1 : 0

  cloud_account_id = var.xshield_changes.cloud_account_id
  region           = var.xshield_changes.region
  vpc_id           = var.vpc_id
  group_name       = var.group_name

  declared_ingress_rules = var.ingress_rules
  declared_egress_rules  = var.egress_rules
}

locals {
  ingress = local.changed ? data.xshield_aws_security_group_rules.this[0].ingress_rules : var.ingress_rules
  egress  = local.changed ? data.xshield_aws_security_group_rules.this[0].egress_rules : var.egress_rules
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

# Held in Terraform's state alone, with nothing in AWS. A plan that stops declaring the group's rules through this
# module deletes it, which is how the Xshield policy checks see such a plan after the plan's own reads of Xshield
# are gone with the module.
resource "terraform_data" "xshield_routed" {
  input = {
    cloud_account_id  = var.xshield_changes.cloud_account_id
    region            = var.xshield_changes.region
    vpc_id            = var.vpc_id
    group_name        = var.group_name
    security_group_id = var.security_group_id
    changed           = local.changed
  }
}

# Applies the AWS resources Xshield rendered for one account and region, and
# tells Xshield what was applied. Every decision is in the snapshot: this module
# only creates what it lists, keyed as it lists it.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = coalesce(var.cloud_account_id, data.aws_caller_identity.current.account_id)
  region     = coalesce(var.region, data.aws_region.current.region)
  workspace  = coalesce(var.workspace, "xshield-enforcement-${local.account_id}-${local.region}")
  snap       = data.xshield_aws_enforcement_snapshot.this
}

data "xshield_aws_enforcement_snapshot" "this" {
  cloud_account_id = local.account_id
  region           = local.region
  version          = var.snapshot_version

  lifecycle {
    postcondition {
      condition     = self.cloud_account_id == data.aws_caller_identity.current.account_id && self.region == data.aws_region.current.region
      error_message = "This snapshot is for ${self.cloud_account_id}/${self.region}, but the AWS provider is configured for ${data.aws_caller_identity.current.account_id}/${data.aws_region.current.region}. Point the AWS provider at the account and region the snapshot is for."
    }
  }
}

# Xshield never unpublishes an account: it withdraws by publishing an empty
# version. So with nothing published, groups it rendered for a pipeline mean the
# provider is reading another tenant or endpoint, and applying would remove them.
data "aws_security_groups" "rendered" {
  count = local.snap.published ? 0 : 1

  filter {
    name   = "tag:ManagedBy"
    values = ["ColorTokens"]
  }
  filter {
    name   = "tag:ct:delivery"
    values = ["pipeline"]
  }

  lifecycle {
    postcondition {
      condition     = length(self.ids) == 0
      error_message = "Xshield has published nothing for ${local.account_id}/${local.region}, yet the account holds security groups Xshield rendered for a pipeline (${join(", ", self.ids)}), and applying would remove them. Check that the xshield provider's endpoint and API key are for the tenant that published them. To remove Xshield's groups on purpose, remove this module from the configuration."
    }
  }
}

# With nothing published the plan reads "No changes", which looks the same as an account whose policy the
# provider cannot see, so the run says which it is.
check "xshield_published" {
  assert {
    condition     = local.snap.published
    error_message = "Xshield has published nothing for ${local.account_id}/${local.region}, so this run creates nothing and sends no receipt. If the account should have policy, check in Xshield that it is set to pipeline delivery and has a deployed policy, and check that the xshield provider's endpoint and API key are for the tenant that owns the account."
  }
}

resource "aws_security_group" "this" {
  for_each = local.snap.security_groups

  name        = each.value.name
  description = each.value.description
  vpc_id      = each.value.vpc_id
  tags        = merge(var.tags, each.value.tags)

  # Xshield drops a group only once no network interface holds it. If one still does, such as an
  # interface AWS has not yet released, fail within minutes rather than hold the pipeline.
  timeouts {
    delete = "5m"
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.snap.ingress_rules

  security_group_id            = aws_security_group.this[each.value.security_group].id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  description                  = each.value.description
  referenced_security_group_id = each.value.referenced_security_group_id
  tags                         = merge(var.tags, each.value.tags)

  # A group's new rules go in before its old ones come out, so access a change keeps is never
  # dropped in between, and a rule AWS refuses leaves the old ones in place. Where old and new
  # together would pass the account's rules per security group, Xshield takes out first the old
  # rules no new one replaces, and the new ones go in at the next apply.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.snap.egress_rules

  security_group_id            = aws_security_group.this[each.value.security_group].id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  description                  = each.value.description
  referenced_security_group_id = each.value.referenced_security_group_id
  tags                         = merge(var.tags, each.value.tags)

  lifecycle {
    create_before_destroy = true
  }
}

# Each group the module creates holds only the rules the snapshot declares for it, so the next
# apply removes a rule added to it outside Terraform. Removing this resource revokes nothing.
locals {
  ingress_keys_by_group = { for key, rule in local.snap.ingress_rules : rule.security_group => key... }
  egress_keys_by_group  = { for key, rule in local.snap.egress_rules : rule.security_group => key... }
}

resource "aws_vpc_security_group_rules_exclusive" "this" {
  for_each = var.enable_exclusive_rules ? local.snap.security_groups : {}

  security_group_id = aws_security_group.this[each.key].id
  ingress_rule_ids  = [for key in lookup(local.ingress_keys_by_group, each.key, []) : aws_vpc_security_group_ingress_rule.this[key].security_group_rule_id]
  egress_rule_ids   = [for key in lookup(local.egress_keys_by_group, each.key, []) : aws_vpc_security_group_egress_rule.this[key].security_group_rule_id]
}

# An instance's interfaces go with the instance, often before discovery tells
# Xshield, so an attachment is planned only while its interface exists: a
# terminated instance never fails the apply. Xshield accepts a receipt that
# leaves such an attachment out.
data "aws_network_interfaces" "present" {
  count = length(local.snap.interface_attachments) > 0 ? 1 : 0

  filter {
    name   = "vpc-id"
    values = distinct([for attachment in values(local.snap.interface_attachments) : local.snap.security_groups[attachment.security_group].vpc_id])
  }
}

locals {
  present_interfaces = { for id in toset(try(data.aws_network_interfaces.present[0].ids, [])) : id => true }
  attachments        = { for key, attachment in local.snap.interface_attachments : key => attachment if lookup(local.present_interfaces, attachment.network_interface_id, false) }
}

# An interface that filled up since Xshield last discovered it has no room for a
# new group, and AWS would refuse the apply. So an attachment neither the last
# receipt holds nor a hand-over offers goes only on an interface with room for every
# new group: the others are left out with a warning, the receipt leaves them out, and
# Xshield refuses the workload once discovery shows the interface full. Only those
# interfaces, and the groups new to them, are read.
data "xshield_enforcement_status" "this" {
  count = length(local.attachments) > 0 ? 1 : 0

  cloud_account_id = local.account_id
  region           = local.region
}

locals {
  held_attachments = { for key in toset(concat(try(keys(data.xshield_enforcement_status.this[0].applied_attachments), []), try(keys(data.xshield_enforcement_status.this[0].handover_attachments), []))) : key => true }
  new_attachments  = { for key, attachment in local.attachments : key => attachment if attachment.slot_limit != null && !lookup(local.held_attachments, key, false) }
}

data "aws_network_interface" "receiving" {
  for_each = toset([for attachment in values(local.new_attachments) : attachment.network_interface_id])

  id = each.key
}

# A new attachment's group can already be on its interface: an apply that attached it
# and then failed sent no receipt, so the run after it finds the attachment new and
# the group in place. Each such group is looked up by name, since its ID is not known
# to a plan that creates it.
data "aws_security_groups" "attaching" {
  for_each = toset([for attachment in values(local.new_attachments) : attachment.security_group])

  filter {
    name   = "group-name"
    values = [local.snap.security_groups[each.key].name]
  }
  filter {
    name   = "vpc-id"
    values = [local.snap.security_groups[each.key].vpc_id]
  }
}

locals {
  new_limits = { for attachment in values(local.new_attachments) : attachment.network_interface_id => attachment.slot_limit... }
  new_groups = { for attachment in values(local.new_attachments) : attachment.network_interface_id => attachment.security_group... }
  # The new groups each interface still has to take. One it already carries takes no further room.
  groups_to_add = {
    for id, interface in data.aws_network_interface.receiving : id => [
      for group in local.new_groups[id] : group
      if length(setintersection(data.aws_security_groups.attaching[group].ids, interface.security_groups)) == 0
    ]
  }
  # An interface is full when the groups it carries and the new groups it still has to take together pass its limit.
  full_interfaces = {
    for id, interface in data.aws_network_interface.receiving : id => try(interface.attachment[0].instance_id, "not attached")
    if length(interface.security_groups) + length(local.groups_to_add[id]) > min(local.new_limits[id]...)
  }
  new_attachment_keys   = { for key in keys(local.new_attachments) : key => true }
  full_interface_ids    = { for id in keys(local.full_interfaces) : id => true }
  attachments_with_room = { for key, attachment in local.attachments : key => attachment if !(lookup(local.new_attachment_keys, key, false) && lookup(local.full_interface_ids, attachment.network_interface_id, false)) }
}

check "interfaces_have_room" {
  assert {
    condition     = length(local.full_interfaces) == 0
    error_message = "These network interfaces carry as many security groups as the account allows, so Xshield's new group was left off them this run, as AWS would refuse it: ${join(", ", [for id, instance in local.full_interfaces : "${id} (${instance})"])}. Xshield refuses these workloads once discovery shows the interfaces full. To enforce them, remove a group from each interface or raise the account's security groups per network interface quota."
  }
}

# Adds the group to the interface and leaves the interface's other groups in
# place, as the cloud connector does.
resource "aws_network_interface_sg_attachment" "this" {
  for_each = local.attachments_with_room

  security_group_id    = aws_security_group.this[each.value.security_group].id
  network_interface_id = each.value.network_interface_id
}

# One parameter per database, function or service its own workspace attaches;
# the aws-group-lookup module reads it by handle.
resource "aws_ssm_parameter" "directory" {
  for_each = local.snap.directory_entries

  name = each.value.parameter_name
  type = "String"
  insecure_value = jsonencode({
    handle             = each.value.handle
    security_group_ids = [for key in each.value.security_groups : aws_security_group.this[key].id]
    slot_limit         = each.value.slot_limit
  })
  tags = merge(var.tags, each.value.tags)
}

# Nothing published means nothing to confirm, so no receipt is created or sent.
resource "xshield_enforcement_receipt" "this" {
  count = local.snap.published ? 1 : 0

  cloud_account_id = local.snap.cloud_account_id
  region           = local.snap.region
  workspace        = local.workspace
  snapshot_version = local.snap.version
  exclusive_rules  = var.enable_exclusive_rules

  security_groups = { for key, group in aws_security_group.this : key => group.id }
  rules = merge(
    { for key, rule in aws_vpc_security_group_ingress_rule.this : key => rule.security_group_rule_id },
    { for key, rule in aws_vpc_security_group_egress_rule.this : key => rule.security_group_rule_id },
  )
  # Recorded as the attachment's import ID, so a lost state can be rebuilt from the receipt.
  attachments = { for key, attachment in aws_network_interface_sg_attachment.this : key => "${attachment.network_interface_id}_${attachment.security_group_id}" }

  depends_on = [aws_ssm_parameter.directory, aws_vpc_security_group_rules_exclusive.this]
}

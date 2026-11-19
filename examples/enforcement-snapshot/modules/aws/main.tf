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
  enforcement_plan = true

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

# A group's name comes from the account's security group name template in Xshield, or is the cloud connector's when the
# account has none, and a VPC holds one group per name. So the name of each group the last receipt does not hold is looked
# up in its VPC, and a group already holding it stops the plan unless it is Xshield's group for that key: one an apply
# created before it failed without a receipt, or the cloud connector's. A workload's group is told apart by its ct:owner tag,
# a cohort group, which has none, by its ct:change-set tag. Groups the last receipt holds are not looked up.
# The filter treats * and ? in a name as wildcards, so a group found under another name is no holder.
locals {
  applied_security_groups = try(data.xshield_aws_enforcement_status.this[0].applied_security_groups, {})
  new_security_groups     = { for key, group in local.snap.security_groups : key => group if lookup(local.applied_security_groups, key, null) == null }
  new_group_identity_tags = { for key, group in local.new_security_groups : key => lookup(group.tags, "ct:kind", "") == "cohort" ? "ct:change-set" : "ct:owner" }
}

data "aws_security_groups" "named" {
  for_each = local.new_security_groups

  filter {
    name   = "group-name"
    values = [each.value.name]
  }
  filter {
    name   = "vpc-id"
    values = [each.value.vpc_id]
  }
}

locals {
  name_holders = { for found in flatten([for key, named in data.aws_security_groups.named : [for id in named.ids : { key = key, id = id }]]) : "${found.key} ${found.id}" => found }
}

data "aws_security_group" "name_holder" {
  for_each = local.name_holders

  id = each.value.id

  lifecycle {
    postcondition {
      condition = self.name != local.new_security_groups[each.value.key].name || (
        lookup(self.tags, "ManagedBy", "") == "ColorTokens" &&
        lookup(self.tags, local.new_group_identity_tags[each.value.key], "") == lookup(local.new_security_groups[each.value.key].tags, local.new_group_identity_tags[each.value.key], "")
      )
      error_message = "Security group ${self.id} in ${self.vpc_id} already has the name ${self.name}, which Xshield gives the group ${each.value.key} this run would create, and it is not Xshield's group for ${each.value.key}. A VPC holds one security group per name, so the plan stopped and nothing was applied. Rename or delete ${self.id}, or change the account's security group name template in Xshield, which names only groups created after the change, then plan again."
    }
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

# Every instance below reads the IDs it needs from these maps, which Terraform builds once. Indexing
# a resource with a key from each.value builds all of its instances for every reference instead, so
# an account's plan took minutes and gigabytes once it had a few hundred workloads.
locals {
  security_group_ids = { for key, group in aws_security_group.this : key => group.id }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.snap.ingress_rules

  security_group_id            = local.security_group_ids[each.value.security_group]
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

  security_group_id            = local.security_group_ids[each.value.security_group]
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
  ingress_keys_by_group     = { for key, rule in local.snap.ingress_rules : rule.security_group => key... }
  egress_keys_by_group      = { for key, rule in local.snap.egress_rules : rule.security_group => key... }
  ingress_rule_ids_by_group = { for group, keys in local.ingress_keys_by_group : group => [for key in keys : aws_vpc_security_group_ingress_rule.this[key].security_group_rule_id] }
  egress_rule_ids_by_group  = { for group, keys in local.egress_keys_by_group : group => [for key in keys : aws_vpc_security_group_egress_rule.this[key].security_group_rule_id] }
}

resource "aws_vpc_security_group_rules_exclusive" "this" {
  for_each = var.enable_exclusive_rules ? local.snap.security_groups : {}

  security_group_id = local.security_group_ids[each.key]
  ingress_rule_ids  = lookup(local.ingress_rule_ids_by_group, each.key, [])
  egress_rule_ids   = lookup(local.egress_rule_ids_by_group, each.key, [])
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
# interfaces, and the groups new to them, are read. A version with network ACL entries
# reads the status too, for the review's account of how far each network ACL reaches,
# and a version with groups reads it for the groups the last receipt holds.
data "xshield_aws_enforcement_status" "this" {
  count = length(local.attachments) > 0 || length(local.snap.network_acl_entries) > 0 || length(local.snap.security_groups) > 0 ? 1 : 0

  cloud_account_id = local.account_id
  region           = local.region
}

locals {
  held_attachments = { for key in toset(concat(try(keys(data.xshield_aws_enforcement_status.this[0].applied_attachments), []), try(keys(data.xshield_aws_enforcement_status.this[0].handover_attachments), []))) : key => true }
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
# place, as the cloud connector does. A version that moves an interface from
# one of Xshield's groups to another, as when a new cohort group supersedes an
# old one, attaches the new group before it detaches the old: an attachment
# the version drops comes off only once Xshield has accepted the receipt, so a
# group, rule or attachment AWS refuses leaves the interface as last applied.
resource "aws_network_interface_sg_attachment" "this" {
  for_each = local.attachments_with_room

  security_group_id    = local.security_group_ids[each.value.security_group]
  network_interface_id = each.value.network_interface_id

  lifecycle {
    create_before_destroy = true
  }
}

# One parameter per database, function or service its own workspace attaches;
# the aws-group-lookup module reads it by handle, and takes only the groups in the
# resource's VPC, as AWS refuses a group from another. The parameters are written
# only once every rule is in place: when AWS refuses any rule, the apply writes or
# changes none of them, so an owner's workspace that runs after the failed apply
# reads what the last complete apply wrote rather than a group missing a rule, and
# no group where no apply has completed yet, as on the first apply after a move
# from connector delivery.
resource "aws_ssm_parameter" "directory" {
  for_each = local.snap.directory_entries

  name = each.value.parameter_name
  type = "String"
  insecure_value = jsonencode({
    handle                    = each.value.handle
    security_group_ids        = [for key in each.value.security_groups : local.security_group_ids[key]]
    security_group_ids_by_vpc = { for key in each.value.security_groups : local.snap.security_groups[key].vpc_id => local.security_group_ids[key]... }
    slot_limit                = each.value.slot_limit
  })
  tags = merge(var.tags, each.value.tags)

  depends_on = [aws_vpc_security_group_ingress_rule.this, aws_vpc_security_group_egress_rule.this]
}

# Each address the malicious IP block template blocks is one entry on the network ACL in front of its workloads,
# denying all traffic from it inbound or to it outbound. Xshield numbers an entry in front of every allow that covers
# its address, and places one only where the network ACL had room when the cloud connector last observed it, so AWS
# refuses one as over its rules per network ACL only after rules are added since. An allow put in front of an entry
# lets its address through until the next apply moves the deny in front of the allow, writing the new number before
# deleting the old, and a move AWS refuses leaves the deny at its old number, behind the allow. An entry changed in AWS,
# or another entry written at its number, stops the plan while the version holds the deny at that number: it is not
# Xshield's, and Terraform deletes an entry by its number alone. Nothing checks the entry at a number Terraform deletes,
# so a move planned once the cloud connector has observed the change, or a version that no longer holds a deny,
# deletes whatever AWS holds there.
#
# The network ACLs are read at plan, so a role without ec2:DescribeNetworkAcls, such as one created before network ACL
# entries, stops the run before anything is written, and so does a network ACL deleted since Xshield planned its entries.
data "aws_network_acls" "present" {
  count = length(local.snap.network_acl_entries) > 0 ? 1 : 0
}

locals {
  present_network_acls = { for id in toset(try(data.aws_network_acls.present[0].ids, [])) : id => true }
  # Xshield never republishes a pinned version, so its entries on a network ACL deleted since are left out rather than
  # stop every plan while the pin is in place.
  network_acl_entries = var.snapshot_version == null ? local.snap.network_acl_entries : {
    for key, entry in local.snap.network_acl_entries : key => entry if lookup(local.present_network_acls, entry.network_acl_id, false)
  }
}

check "pinned_network_acl_entries_present" {
  assert {
    condition     = length(local.network_acl_entries) == length(local.snap.network_acl_entries)
    error_message = "The pinned version ${coalesce(var.snapshot_version, "-")} has entries on network ACLs that no longer exist in ${local.account_id}/${local.region}, so they are left out: ${join(", ", sort(setsubtract(keys(local.snap.network_acl_entries), keys(local.network_acl_entries))))}. Xshield refuses a receipt that leaves them out until the cloud connector has observed those network ACLs gone, and until then the apply ends with the receipt refused. The directory parameters this version removes, and with exclusive rules the rules it drops from a group, are removed before the receipt is sent; the security groups, rules, attachments and network ACL entries it deletes stay in place until a receipt is accepted. Plan and apply again once the cloud connector has observed them gone."
  }
}

resource "aws_network_acl_rule" "this" {
  for_each = local.network_acl_entries

  network_acl_id  = each.value.network_acl_id
  egress          = each.value.egress
  rule_number     = each.value.rule_number
  rule_action     = "deny"
  protocol        = "-1"
  cidr_block      = each.value.cidr_ipv4
  ipv6_cidr_block = each.value.cidr_ipv6

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [rule_action, protocol, cidr_block, ipv6_cidr_block, from_port, to_port, icmp_type, icmp_code]

    precondition {
      condition     = lookup(local.present_network_acls, each.value.network_acl_id, false)
      error_message = "Network ACL ${each.value.network_acl_id} no longer exists in ${local.account_id}/${local.region}, so AWS would refuse its entry ${each.key}, and nothing was applied. Xshield stops planning entries for it once the cloud connector observes it gone; plan again after that."
    }

    # Terraform reads and deletes an entry by its rule number alone, so an entry written at Xshield's number outside
    # Terraform would otherwise be taken into state, and a later move or removal of the deny would delete it.
    postcondition {
      condition     = self.rule_action == "deny" && self.protocol == "-1" && coalesce(self.cidr_block, "-") == coalesce(each.value.cidr_ipv4, "-") && coalesce(self.ipv6_cidr_block, "-") == coalesce(each.value.cidr_ipv6, "-")
      error_message = "AWS now holds another entry at rule number ${each.value.rule_number} ${each.value.egress ? "outbound" : "inbound"} of network ACL ${each.value.network_acl_id}, where Xshield's deny of ${coalesce(each.value.cidr_ipv4, each.value.cidr_ipv6)} was: it ${self.rule_action}s protocol ${self.protocol} for ${coalesce(self.cidr_block, self.ipv6_cidr_block, "-")}. It is not Xshield's, so the plan stopped before anything was applied: Terraform deletes an entry by its rule number, and would delete this one when the deny moves or is removed. Run terraform state rm on aws_network_acl_rule.this[\"${each.key}\"] of this module so that Terraform stops holding it, then plan again; if an import block brought it in, as recovery/ does, leave that import out instead, under network_acl_entries in recovery.tf's skipped_imports. Once the cloud connector observes the network ACL, Xshield gives the deny another number. A pinned snapshot_version keeps this number, so until the pin is removed the apply fails on this entry with NetworkAclEntryAlreadyExists."
    }
  }
}

# Nothing published means nothing to confirm, so no receipt is created or sent.
resource "xshield_aws_enforcement_receipt" "this" {
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
  # Each entry's import ID; null when there is none, as a receipt sent before network ACL entries holds.
  network_acl_entries = length(aws_network_acl_rule.this) == 0 ? null : { for key, entry in aws_network_acl_rule.this : key => "${entry.network_acl_id}:${entry.rule_number}:-1:${entry.egress}" }

  depends_on = [aws_ssm_parameter.directory, aws_vpc_security_group_rules_exclusive.this]
}

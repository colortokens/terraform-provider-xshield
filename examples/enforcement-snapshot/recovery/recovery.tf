# Rebuilds a lost enforcement state from the last receipt. Add this file to the enforcement workspace,
# set snapshot_version = data.xshield_enforcement_status.recover.applied_version on the module, apply
# once, then delete this file and the pin.
#
# The plan shows every resource as an import, network ACL entries among them, nothing to add and nothing
# to destroy. It also shows an in-place change on each security group and each directory parameter: an
# import cannot read a group's revoke_rules_on_delete, and it reads a parameter into value where the module
# declares insecure_value, so the parameter is written again with the value it holds. No group, rule,
# attachment or network ACL entry changes.
# A rule added to an Xshield group outside Terraform shows as an in-place change of that group's
# exclusive rules resource, and the apply removes it.
# If an instance in the last receipt has since been terminated, the receipt is also sent again, without
# that instance's attachment. If a network ACL in the last receipt has since been deleted, its entries are
# left out, a check names them, and the receipt is sent again without them. Xshield accepts it once the
# cloud connector has observed the network ACL gone; until then the apply ends with that refusal once the
# state is rebuilt, so run it again after the cloud connector's next observation.
# An object of the last receipt deleted outside Terraform since has nothing to import: the plan stops with "Cannot
# import non-existent remote object" and names its address. Add the key in its brackets to skipped_imports, under its
# kind, and the apply creates it again.
data "aws_caller_identity" "recover" {}
data "aws_region" "recover" {}

data "xshield_enforcement_status" "recover" {
  cloud_account_id = data.aws_caller_identity.recover.account_id
  region           = data.aws_region.recover.region
}

data "xshield_aws_enforcement_snapshot" "recover" {
  cloud_account_id = data.aws_caller_identity.recover.account_id
  region           = data.aws_region.recover.region
  version          = data.xshield_enforcement_status.recover.applied_version
}

# Keys of the last receipt's objects not to import, by kind: one deleted outside Terraform since, which the apply creates
# again, or a network ACL entry whose receipted number AWS now holds another entry at. That one stops the plan, which
# names the entry's key: add it under network_acl_entries. The apply then rebuilds the rest of the state and fails on
# that entry with NetworkAclEntryAlreadyExists, as the pinned version keeps its number. Delete this file and the pin,
# and run the workspace again once the cloud connector has observed the network ACL: Xshield gives the deny another
# number, and the run writes it there.
variable "skipped_imports" {
  type = object({
    security_groups     = optional(set(string), [])
    rules               = optional(set(string), [])
    attachments         = optional(set(string), [])
    network_acl_entries = optional(set(string), [])
  })
  default  = {}
  nullable = false
}

locals {
  recovered_security_groups = { for k in setsubtract(keys(data.xshield_enforcement_status.recover.applied_security_groups), var.skipped_imports.security_groups) : k => data.xshield_enforcement_status.recover.applied_security_groups[k] }
  recovered_rules           = { for k in setsubtract(keys(data.xshield_enforcement_status.recover.applied_rules), var.skipped_imports.rules) : k => data.xshield_enforcement_status.recover.applied_rules[k] }
  # An interface that went with its instance since the last receipt has no attachment to import: the module declares
  # none for it.
  recovered_attachments = { for k in setsubtract(setintersection(keys(data.xshield_enforcement_status.recover.applied_attachments), module.xshield_enforcement.attachment_keys), var.skipped_imports.attachments) : k => data.xshield_enforcement_status.recover.applied_attachments[k] }
  # An entry on a network ACL deleted since the last receipt has nothing to import: the module declares none for it.
  recovered_network_acl_entries = { for k in setsubtract(setintersection(keys(data.xshield_enforcement_status.recover.applied_network_acl_entries), module.xshield_enforcement.network_acl_entry_keys), var.skipped_imports.network_acl_entries) : k => data.xshield_enforcement_status.recover.applied_network_acl_entries[k] }
}

import {
  for_each = local.recovered_security_groups
  to       = module.xshield_enforcement.aws_security_group.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in local.recovered_rules : k => v if can(data.xshield_aws_enforcement_snapshot.recover.ingress_rules[k]) }
  to       = module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in local.recovered_rules : k => v if can(data.xshield_aws_enforcement_snapshot.recover.egress_rules[k]) }
  to       = module.xshield_enforcement.aws_vpc_security_group_egress_rule.this[each.key]
  id       = each.value
}

import {
  for_each = local.recovered_attachments
  to       = module.xshield_enforcement.aws_network_interface_sg_attachment.this[each.key]
  id       = each.value
}

import {
  for_each = local.recovered_network_acl_entries
  to       = module.xshield_enforcement.aws_network_acl_rule.this[each.key]
  id       = each.value
}

import {
  for_each = { for handle, entry in data.xshield_aws_enforcement_snapshot.recover.directory_entries : handle => entry.parameter_name }
  to       = module.xshield_enforcement.aws_ssm_parameter.directory[each.key]
  id       = each.value
}

import {
  for_each = module.xshield_enforcement.exclusive_rules_enabled ? local.recovered_security_groups : {}
  to       = module.xshield_enforcement.aws_vpc_security_group_rules_exclusive.this[each.key]
  id       = each.value
}

import {
  to = module.xshield_enforcement.xshield_enforcement_receipt.this[0]
  id = "${data.aws_caller_identity.recover.account_id}/${data.aws_region.recover.region}"
}

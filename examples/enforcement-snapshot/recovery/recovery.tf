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
# left out and a check names them; Xshield refuses a receipt without them, so the apply ends with that
# refusal once the state is rebuilt. Delete this file and the pin, and run the workspace again once the
# cloud connector has observed the network ACL gone.
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

import {
  for_each = data.xshield_enforcement_status.recover.applied_security_groups
  to       = module.xshield_enforcement.aws_security_group.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in data.xshield_enforcement_status.recover.applied_rules : k => v if can(data.xshield_aws_enforcement_snapshot.recover.ingress_rules[k]) }
  to       = module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in data.xshield_enforcement_status.recover.applied_rules : k => v if can(data.xshield_aws_enforcement_snapshot.recover.egress_rules[k]) }
  to       = module.xshield_enforcement.aws_vpc_security_group_egress_rule.this[each.key]
  id       = each.value
}

# An interface that went with its instance since the last receipt has no attachment to import: the
# module declares none for it.
import {
  for_each = { for k in setintersection(keys(data.xshield_enforcement_status.recover.applied_attachments), module.xshield_enforcement.attachment_keys) : k => data.xshield_enforcement_status.recover.applied_attachments[k] }
  to       = module.xshield_enforcement.aws_network_interface_sg_attachment.this[each.key]
  id       = each.value
}

# An entry on a network ACL deleted since the last receipt has nothing to import: the module declares none for it.
import {
  for_each = { for k in setintersection(keys(data.xshield_enforcement_status.recover.applied_network_acl_entries), module.xshield_enforcement.network_acl_entry_keys) : k => data.xshield_enforcement_status.recover.applied_network_acl_entries[k] }
  to       = module.xshield_enforcement.aws_network_acl_rule.this[each.key]
  id       = each.value
}

import {
  for_each = { for handle, entry in data.xshield_aws_enforcement_snapshot.recover.directory_entries : handle => entry.parameter_name }
  to       = module.xshield_enforcement.aws_ssm_parameter.directory[each.key]
  id       = each.value
}

import {
  for_each = module.xshield_enforcement.exclusive_rules_enabled ? data.xshield_enforcement_status.recover.applied_security_groups : {}
  to       = module.xshield_enforcement.aws_vpc_security_group_rules_exclusive.this[each.key]
  id       = each.value
}

import {
  to = module.xshield_enforcement.xshield_enforcement_receipt.this[0]
  id = "${data.aws_caller_identity.recover.account_id}/${data.aws_region.recover.region}"
}

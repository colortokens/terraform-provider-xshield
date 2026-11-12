# Rebuilds a lost enforcement state from the last receipt. Add this file to the enforcement workspace,
# set snapshot_version = data.xshield_enforcement_status.recover.applied_version on the module, apply
# once, then delete this file and the pin.
#
# The plan shows every resource as an import, nothing to add and nothing to destroy. It also shows an
# in-place change on each security group and each directory parameter: an import cannot read a group's
# revoke_rules_on_delete, and it reads a parameter into value where the module declares insecure_value,
# so the parameter is written again with the value it holds. No group, rule or attachment changes.
# If an instance in the last receipt has since been terminated, the receipt is also sent again, without
# that instance's attachment.
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
  for_each = { for k, v in data.xshield_enforcement_status.recover.applied_rules : k => v if contains(keys(data.xshield_aws_enforcement_snapshot.recover.ingress_rules), k) }
  to       = module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in data.xshield_enforcement_status.recover.applied_rules : k => v if contains(keys(data.xshield_aws_enforcement_snapshot.recover.egress_rules), k) }
  to       = module.xshield_enforcement.aws_vpc_security_group_egress_rule.this[each.key]
  id       = each.value
}

# An interface that went with its instance since the last receipt has no attachment to import: the
# module declares none for it.
import {
  for_each = { for k, v in data.xshield_enforcement_status.recover.applied_attachments : k => v if contains(module.xshield_enforcement.attachment_keys, k) }
  to       = module.xshield_enforcement.aws_network_interface_sg_attachment.this[each.key]
  id       = each.value
}

import {
  for_each = { for handle, entry in data.xshield_aws_enforcement_snapshot.recover.directory_entries : handle => entry.parameter_name }
  to       = module.xshield_enforcement.aws_ssm_parameter.directory[each.key]
  id       = each.value
}

import {
  to = module.xshield_enforcement.xshield_enforcement_receipt.this[0]
  id = "${data.aws_caller_identity.recover.account_id}/${data.aws_region.recover.region}"
}

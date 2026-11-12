# Takes over an account from connector delivery without creating its groups again: the plan imports
# the groups, rules and attachments the cloud connector created, which stay in place and enforced, and
# the directory parameters an earlier spell on pipeline delivery left, and adds only what is missing.
# Add this file to the enforcement workspace for the first apply after the account moves to pipeline
# delivery, then delete it.
data "aws_caller_identity" "handover" {}
data "aws_region" "handover" {}

data "xshield_enforcement_status" "handover" {
  cloud_account_id = data.aws_caller_identity.handover.account_id
  region           = data.aws_region.handover.region
}

data "xshield_aws_enforcement_snapshot" "handover" {
  cloud_account_id = data.aws_caller_identity.handover.account_id
  region           = data.aws_region.handover.region
}

import {
  for_each = data.xshield_enforcement_status.handover.handover_security_groups
  to       = module.xshield_enforcement.aws_security_group.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in data.xshield_enforcement_status.handover.handover_rules : k => v if contains(keys(data.xshield_aws_enforcement_snapshot.handover.ingress_rules), k) }
  to       = module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this[each.key]
  id       = each.value
}

import {
  for_each = { for k, v in data.xshield_enforcement_status.handover.handover_rules : k => v if contains(keys(data.xshield_aws_enforcement_snapshot.handover.egress_rules), k) }
  to       = module.xshield_enforcement.aws_vpc_security_group_egress_rule.this[each.key]
  id       = each.value
}

# An interface that went with its instance since the connector last looked has no attachment to
# import: the module declares none for it.
import {
  for_each = { for k, v in data.xshield_enforcement_status.handover.handover_attachments : k => v if contains(module.xshield_enforcement.attachment_keys, k) }
  to       = module.xshield_enforcement.aws_network_interface_sg_attachment.this[each.key]
  id       = each.value
}

data "aws_ssm_parameters_by_path" "handover" {
  path      = "/colortokens/v1"
  recursive = true
}

import {
  for_each = { for k, d in data.xshield_aws_enforcement_snapshot.handover.directory_entries : k => d.parameter_name if contains(data.aws_ssm_parameters_by_path.handover.names, d.parameter_name) }
  to       = module.xshield_enforcement.aws_ssm_parameter.directory[each.key]
  id       = each.value
}

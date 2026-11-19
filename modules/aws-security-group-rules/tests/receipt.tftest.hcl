# terraform test, offline: both providers are mocked. Whenever the module reads the group's rules from Xshield, the
# mock answers as Xshield does for the group web while change set cs-1 narrows it and change set cs-2 is reverted.

mock_provider "aws" {}

mock_provider "xshield" {
  mock_data "xshield_aws_security_group_rules" {
    defaults = {
      published         = true
      version           = "v7"
      security_group_id = "sg-0example"
      change_sets       = { cs-1 = "narrowing", cs-2 = "restoring" }
      ingress_rules = {
        ssh_office = {
          ip_protocol    = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      egress_rules  = {}
      revoked_rules = ["ingress/https_all"]
      pending_rules = []
    }
  }

  # A receipt's ID is a lowercase UUID, which the applied receipt's receipt_id must be.
  mock_resource "xshield_aws_security_group_changes_receipt" {
    defaults = { id = "0f8fad5b-d9cb-469f-a165-70867728950e" }
  }
}

variables {
  vpc_id            = "vpc-0example"
  group_name        = "web"
  security_group_id = "sg-0example"

  ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
}

run "a_changed_group_reports_the_read_its_rules_came_from_before_and_after_them" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
    receipt_label   = "owner-web"
  }

  assert {
    condition     = length(xshield_aws_security_group_changes_receipt.applying) == 1 && length(xshield_aws_security_group_changes_receipt.applied) == 1
    error_message = "a group an approved change applies to must send one applying and one applied receipt"
  }
  assert {
    condition = (
      xshield_aws_security_group_changes_receipt.applying[0].stage == "applying"
      && xshield_aws_security_group_changes_receipt.applied[0].stage == "applied"
      && xshield_aws_security_group_changes_receipt.applying[0].receipt_id == null
    )
    error_message = "one receipt must be sent at stage applying under a generated ID and the other at stage applied"
  }
  assert {
    condition = alltrue([for receipt in [xshield_aws_security_group_changes_receipt.applying[0], xshield_aws_security_group_changes_receipt.applied[0]] : (
      receipt.cloud_account_id == data.xshield_aws_security_group_rules.this[0].cloud_account_id
      && receipt.region == data.xshield_aws_security_group_rules.this[0].region
      && receipt.version == data.xshield_aws_security_group_rules.this[0].version
      && receipt.version == "v7"
      && receipt.groups == tomap({ (data.xshield_aws_security_group_rules.this[0].security_group_id) = data.xshield_aws_security_group_rules.this[0].change_sets })
      && receipt.groups == tomap({ sg-0example = tomap({ cs-1 = "narrowing", cs-2 = "restoring" }) })
      && receipt.label == "owner-web"
    )])
    error_message = "both receipts must report the account, region, version and change sets of the read the group's rules came from, by the group ID Xshield served, with the label passed"
  }
}

run "a_changed_group_applies_its_rules_between_two_receipts_under_one_id" {
  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
  }

  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["ssh_office"])
    error_message = "the apply must declare the rules Xshield serves"
  }
  assert {
    condition = (
      xshield_aws_security_group_changes_receipt.applied[0].receipt_id == xshield_aws_security_group_changes_receipt.applying[0].id
      && xshield_aws_security_group_changes_receipt.applied[0].receipt_id != null
    )
    error_message = "the applied receipt must be sent under the applying receipt's ID"
  }
}

run "a_group_no_change_applies_to_sends_no_receipt" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { db = ["vpc-0example"] } }
  }

  assert {
    condition     = length(xshield_aws_security_group_changes_receipt.applying) + length(xshield_aws_security_group_changes_receipt.applied) == 0
    error_message = "a group no change applies to must send no receipt"
  }
}

run "nothing_published_sends_no_receipt" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = {} }
  }

  assert {
    condition     = length(xshield_aws_security_group_changes_receipt.applying) + length(xshield_aws_security_group_changes_receipt.applied) == 0
    error_message = "with nothing published the module must send no receipt"
  }
}

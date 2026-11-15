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

run "a_changed_group_reports_the_read_its_rules_came_from" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
    receipt_label   = "owner-web"
  }

  assert {
    condition     = length(xshield_aws_security_group_changes_receipt.this) == 1
    error_message = "a group an approved change applies to must send one receipt"
  }
  assert {
    condition = (
      xshield_aws_security_group_changes_receipt.this[0].cloud_account_id == data.xshield_aws_security_group_rules.this[0].cloud_account_id
      && xshield_aws_security_group_changes_receipt.this[0].region == data.xshield_aws_security_group_rules.this[0].region
      && xshield_aws_security_group_changes_receipt.this[0].version == data.xshield_aws_security_group_rules.this[0].version
      && xshield_aws_security_group_changes_receipt.this[0].version == "v7"
    )
    error_message = "the receipt must report the account, region and version of the read the group's rules came from"
  }
  assert {
    condition     = xshield_aws_security_group_changes_receipt.this[0].groups == tomap({ (data.xshield_aws_security_group_rules.this[0].security_group_id) = data.xshield_aws_security_group_rules.this[0].change_sets })
    error_message = "the receipt must report the group by the ID Xshield served, with each change set in the state it was read in"
  }
  assert {
    condition     = xshield_aws_security_group_changes_receipt.this[0].groups == tomap({ sg-0example = tomap({ cs-1 = "narrowing", cs-2 = "restoring" }) })
    error_message = "the receipt must list both change sets of sg-0example in the states the mock served"
  }
  assert {
    condition     = xshield_aws_security_group_changes_receipt.this[0].label == "owner-web"
    error_message = "the receipt must carry the label the caller passes"
  }
}

run "a_changed_group_applies_its_rules_and_its_receipt" {
  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
  }

  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["ssh_office"]) && length(xshield_aws_security_group_changes_receipt.this) == 1
    error_message = "the apply must declare the rules Xshield serves and send one receipt"
  }
}

run "a_group_no_change_applies_to_sends_no_receipt" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { db = ["vpc-0example"] } }
  }

  assert {
    condition     = length(xshield_aws_security_group_changes_receipt.this) == 0
    error_message = "a group no change applies to must send no receipt"
  }
}

run "nothing_published_sends_no_receipt" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = {} }
  }

  assert {
    condition     = length(xshield_aws_security_group_changes_receipt.this) == 0
    error_message = "with nothing published the module must send no receipt"
  }
}

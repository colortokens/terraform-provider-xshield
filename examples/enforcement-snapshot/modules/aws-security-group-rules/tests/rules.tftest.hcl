# terraform test, offline: both providers are mocked. The caller declares two ingress and two egress rules for
# the group web in vpc-0example. Whenever the module reads the group's rules from Xshield, the mock answers as
# Xshield does once it has left one rule out in each direction, so each run shows where the declared rules came
# from.

mock_provider "aws" {}

mock_provider "xshield" {
  mock_data "xshield_aws_security_group_rules" {
    defaults = {
      published = true
      version   = "v7"
      ingress_rules = {
        ssh_office = {
          ip_protocol    = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      egress_rules = {
        dns_resolver = {
          ip_protocol    = "udp", from_port = 53, to_port = 53, cidr_ipv4 = "10.0.0.2/32", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      revoked_rules = ["ingress/https_all", "egress/all"]
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
  egress_rules = {
    all          = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
    dns_resolver = { ip_protocol = "udp", from_port = 53, to_port = 53, cidr_ipv4 = "10.0.0.2/32" }
  }
}

# Xshield lists no changed group at all, as for an account and region with nothing published.
run "no_changed_group_declares_the_callers_rules_and_reads_nothing_from_xshield" {
  command = apply

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = {} }
  }

  assert {
    condition     = length(data.xshield_aws_security_group_rules.this) == 0
    error_message = "with no changed group the module must not read the group's rules from Xshield"
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["https_all", "ssh_office"]) && toset(keys(aws_vpc_security_group_egress_rule.this)) == toset(["all", "dns_resolver"])
    error_message = "with no changed group the module must declare exactly the rules the caller passes"
  }
}

# No change is published for the group: another group in the same VPC has one, and this group has none.
run "no_change_declares_the_callers_rules_and_reads_nothing_from_xshield" {
  command = apply

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { db = ["vpc-0example"] } }
  }

  assert {
    condition     = length(data.xshield_aws_security_group_rules.this) == 0
    error_message = "a group no change applies to must not read its rules from Xshield"
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["https_all", "ssh_office"]) && toset(keys(aws_vpc_security_group_egress_rule.this)) == toset(["all", "dns_resolver"])
    error_message = "the module must declare exactly the rules the caller passes, under the caller's keys"
  }
  assert {
    condition = alltrue([
      aws_vpc_security_group_ingress_rule.this["https_all"].security_group_id == "sg-0example",
      aws_vpc_security_group_ingress_rule.this["https_all"].ip_protocol == "tcp",
      aws_vpc_security_group_ingress_rule.this["https_all"].from_port == 443,
      aws_vpc_security_group_ingress_rule.this["https_all"].to_port == 443,
      aws_vpc_security_group_ingress_rule.this["https_all"].cidr_ipv4 == "0.0.0.0/0",
      aws_vpc_security_group_ingress_rule.this["ssh_office"].from_port == 22,
      aws_vpc_security_group_ingress_rule.this["ssh_office"].cidr_ipv4 == "10.0.0.0/8",
      aws_vpc_security_group_egress_rule.this["all"].security_group_id == "sg-0example",
      aws_vpc_security_group_egress_rule.this["all"].ip_protocol == "-1",
      aws_vpc_security_group_egress_rule.this["all"].cidr_ipv4 == "0.0.0.0/0",
      aws_vpc_security_group_egress_rule.this["dns_resolver"].from_port == 53,
      aws_vpc_security_group_egress_rule.this["dns_resolver"].cidr_ipv4 == "10.0.0.2/32",
    ])
    error_message = "each rule must carry the caller's arguments and belong to the caller's group"
  }
}

run "a_change_for_the_group_in_its_vpc_takes_the_rules_from_xshield" {
  command = apply

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example", "vpc-0other"] } }
  }

  assert {
    condition     = length(data.xshield_aws_security_group_rules.this) == 1
    error_message = "a group an approved change applies to must read its rules from Xshield"
  }
  assert {
    condition = alltrue([
      data.xshield_aws_security_group_rules.this[0].cloud_account_id == "111111111111",
      data.xshield_aws_security_group_rules.this[0].region == "us-east-1",
      data.xshield_aws_security_group_rules.this[0].vpc_id == "vpc-0example",
      data.xshield_aws_security_group_rules.this[0].group_name == "web",
      toset(keys(data.xshield_aws_security_group_rules.this[0].declared_ingress_rules)) == toset(["https_all", "ssh_office"]),
      toset(keys(data.xshield_aws_security_group_rules.this[0].declared_egress_rules)) == toset(["all", "dns_resolver"]),
    ])
    error_message = "Xshield must be asked about this group, by its account, region, VPC and name, with every rule the caller declares"
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["ssh_office"]) && toset(keys(aws_vpc_security_group_egress_rule.this)) == toset(["dns_resolver"])
    error_message = "the module must declare the rules Xshield returns, so a rule Xshield left out is not declared"
  }
  assert {
    condition = alltrue([
      aws_vpc_security_group_ingress_rule.this["ssh_office"].security_group_id == "sg-0example",
      aws_vpc_security_group_ingress_rule.this["ssh_office"].cidr_ipv4 == "10.0.0.0/8",
      aws_vpc_security_group_egress_rule.this["dns_resolver"].security_group_id == "sg-0example",
      aws_vpc_security_group_egress_rule.this["dns_resolver"].cidr_ipv4 == "10.0.0.2/32",
    ])
    error_message = "a rule Xshield keeps must stay as the caller declared it, in the caller's group"
  }
}

# The change is for a group of the same name in another VPC, so this group is unchanged and its rules come back.
run "a_change_for_the_same_name_in_another_vpc_leaves_the_group_unchanged" {
  command = apply

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0other"] } }
  }

  assert {
    condition     = length(data.xshield_aws_security_group_rules.this) == 0
    error_message = "a change for the same group name in another VPC must not make this group read its rules from Xshield"
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["https_all", "ssh_office"]) && toset(keys(aws_vpc_security_group_egress_rule.this)) == toset(["all", "dns_resolver"])
    error_message = "a group whose VPC has no change must declare exactly the rules the caller passes"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["https_all"].cidr_ipv4 == "0.0.0.0/0" && aws_vpc_security_group_egress_rule.this["all"].cidr_ipv4 == "0.0.0.0/0"
    error_message = "the rules a change for another VPC narrows must stay as the caller declared them here"
  }
}

# The record the policy checks read: who the group is, and whether its last apply carried an approved change.
run "an_unchanged_group_keeps_a_record_in_state_that_says_so" {
  command = apply

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { db = ["vpc-0example"] } }
  }

  assert {
    condition = terraform_data.xshield_routed.output == {
      cloud_account_id  = "111111111111", region = "us-east-1", vpc_id = "vpc-0example", group_name = "web",
      security_group_id = "sg-0example", changed = false
    }
    error_message = "the record must name the account, region, VPC and group, and say no change applied"
  }
}

run "a_changed_group_keeps_a_record_in_state_that_says_so" {
  command = apply

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
  }

  assert {
    condition = terraform_data.xshield_routed.output == {
      cloud_account_id  = "111111111111", region = "us-east-1", vpc_id = "vpc-0example", group_name = "web",
      security_group_id = "sg-0example", changed = true
    }
    error_message = "the record must say an approved change applied to the group at this apply"
  }
}

# aws_security_group gives a group declared with name_prefix its name only at apply. With no change published for
# the account and region, no name can match one, so the plan must not need it.
run "a_group_whose_name_is_known_only_at_apply_plans_while_no_change_is_published" {
  command = plan

  module {
    source = "./tests/fixtures/name-from-apply"
  }

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = {} }
  }

  assert {
    condition     = output.ingress_keys == tolist(["https_all"])
    error_message = "with no change published, a group named only at apply must plan with the rules the caller passes"
  }
}

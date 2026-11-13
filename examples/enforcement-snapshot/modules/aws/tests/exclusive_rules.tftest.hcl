# terraform test, offline: both providers are mocked. Each group the module creates holds
# only the rules the snapshot declares for it, so a rule added outside Terraform is removed
# at the next apply. The snapshot has a workload's group with ingress and egress rules, a
# cohort group with one rule, and a group with none.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }
  mock_data "aws_security_groups" {
    defaults = { ids = [] }
  }
  mock_data "aws_network_interfaces" {
    defaults = { ids = [] }
  }
}

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v7"
      security_groups = {
        "web-1" = {
          name        = "ct-policy-0000000000b1"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
        "ct-cohort-0123456789abcdef" = {
          name        = "ct-cohort-0123456789abcdef"
          description = "ColorTokens split cohort group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:delivery" = "pipeline" }
        }
        "batch-1" = {
          name        = "ct-policy-0000000000b2"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules = {
        "web-1/in/tcp/443/0.0.0.0/0" = {
          security_group = "web-1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "0.0.0.0/0", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]", tags = {}
        }
        "web-1/in/tcp/22/203.0.113.7/32" = {
          security_group = "web-1", ip_protocol = "tcp", from_port = 22, to_port = 22
          cidr_ipv4      = "203.0.113.7/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Admin]", tags = {}
        }
        "ct-cohort-0123456789abcdef/in/tcp/443/sg-0web" = {
          security_group = "ct-cohort-0123456789abcdef", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = "sg-0web"
          description    = null, tags = {}
        }
      }
      egress_rules = {
        "web-1/out/tcp/443/pl-0a1b2c3d" = {
          security_group = "web-1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = null, prefix_list_id = "pl-0a1b2c3d", referenced_security_group_id = null
          description    = "ColorTokens authored enforce [SaaS endpoints]", tags = {}
        }
      }
      interface_attachments       = {}
      directory_entries           = {}
      assets                      = {}
      withdrawing_security_groups = []
    }
  }
}

run "each_created_group_holds_exactly_its_own_rules" {
  command = apply

  assert {
    condition     = toset(keys(aws_vpc_security_group_rules_exclusive.this)) == toset(keys(aws_security_group.this))
    error_message = "every group the module creates, cohort groups included, gets one exclusive rules resource"
  }
  assert {
    condition = alltrue([
      for key, group in aws_security_group.this : aws_vpc_security_group_rules_exclusive.this[key].security_group_id == group.id
    ])
    error_message = "each exclusive rules resource names its own group"
  }
  assert {
    condition = aws_vpc_security_group_rules_exclusive.this["web-1"].ingress_rule_ids == toset([
      aws_vpc_security_group_ingress_rule.this["web-1/in/tcp/443/0.0.0.0/0"].security_group_rule_id,
      aws_vpc_security_group_ingress_rule.this["web-1/in/tcp/22/203.0.113.7/32"].security_group_rule_id,
    ])
    error_message = "a group's ingress set is exactly its own ingress rules"
  }
  assert {
    condition     = aws_vpc_security_group_rules_exclusive.this["web-1"].egress_rule_ids == toset([aws_vpc_security_group_egress_rule.this["web-1/out/tcp/443/pl-0a1b2c3d"].security_group_rule_id])
    error_message = "a group's egress set is exactly its own egress rules"
  }
  assert {
    condition = (
      aws_vpc_security_group_rules_exclusive.this["ct-cohort-0123456789abcdef"].ingress_rule_ids == toset([aws_vpc_security_group_ingress_rule.this["ct-cohort-0123456789abcdef/in/tcp/443/sg-0web"].security_group_rule_id])
      && length(aws_vpc_security_group_rules_exclusive.this["ct-cohort-0123456789abcdef"].egress_rule_ids) == 0
    )
    error_message = "a cohort group holds only its own rule, and no other group's"
  }
  assert {
    condition     = length(aws_vpc_security_group_rules_exclusive.this["batch-1"].ingress_rule_ids) == 0 && length(aws_vpc_security_group_rules_exclusive.this["batch-1"].egress_rule_ids) == 0
    error_message = "a group with no rule gets empty sets, so any rule added to it is removed"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].exclusive_rules == true && output.exclusive_rules_enabled == true
    error_message = "the receipt and the output say the groups hold only their declared rules"
  }
}

run "turned_off_creates_none" {
  command = apply

  variables {
    enable_exclusive_rules = false
  }

  assert {
    condition     = length(aws_vpc_security_group_rules_exclusive.this) == 0 && length(aws_security_group.this) == 3
    error_message = "turned off, no exclusive rules resource is created and the groups still are"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].exclusive_rules == false && output.exclusive_rules_enabled == false
    error_message = "turned off, the receipt and the output say a rule added by hand stays"
  }
}

run "nothing_published_creates_none" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published                   = false
      version                     = null
      security_groups             = {}
      ingress_rules               = {}
      egress_rules                = {}
      interface_attachments       = {}
      directory_entries           = {}
      assets                      = {}
      withdrawing_security_groups = []
    }
  }

  expect_failures = [check.xshield_published]

  assert {
    condition     = length(aws_vpc_security_group_rules_exclusive.this) == 0
    error_message = "with nothing published there is no group to hold rules"
  }
}

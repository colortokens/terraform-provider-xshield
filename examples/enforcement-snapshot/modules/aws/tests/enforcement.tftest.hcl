# terraform test, offline: both providers are mocked, and the snapshot below is
# shaped like what Xshield serves: one instance with two interfaces, and one
# database its own workspace attaches.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }
  mock_data "aws_security_groups" {
    defaults = { ids = [] }
  }
  mock_data "aws_network_interfaces" {
    defaults = { ids = ["eni-0a1", "eni-0a1b", "eni-legacy"] }
  }
  mock_data "aws_network_interface" {
    defaults = { security_groups = ["sg-0customer1", "sg-0customer2"], attachment = [] }
  }
}

mock_provider "xshield" {
  mock_data "xshield_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v42"
      security_groups = {
        "i-0a1" = {
          name        = "ct-policy-3f2a9c1d7e4b"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:owner" = "3f2a9c1d7e4b5a60", "ct:delivery" = "pipeline", Name = "ct-policy-i-0a1" }
        }
        "rds/orders-db" = {
          name        = "ct-policy-8e7d6c5b4a39"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:owner" = "8e7d6c5b4a392817", "ct:delivery" = "pipeline", Name = "ct-policy-rds/orders-db" }
        }
      }
      ingress_rules = {
        "i-0a1/in/tcp/443/0.0.0.0/0" = {
          security_group = "i-0a1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "0.0.0.0/0", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce t=tmpl-web r=321b0542e7696510"
          tags           = { ManagedBy = "ColorTokens", "ct:origin" = "authored", "ct:mode" = "enforce", "ct:template" = "tmpl-web", "ct:rule" = "321b0542e7696510" }
        }
        "i-0a1/in/tcp/443/::/0" = {
          security_group = "i-0a1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = "::/0", prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce t=tmpl-web r=321b0542e7696510"
          tags           = { ManagedBy = "ColorTokens", "ct:origin" = "authored", "ct:mode" = "enforce", "ct:template" = "tmpl-web", "ct:rule" = "321b0542e7696510" }
        }
        "i-0a1/in/-1/any/10.0.0.0/8" = {
          security_group = "i-0a1", ip_protocol = "-1", from_port = null, to_port = null
          cidr_ipv4      = "10.0.0.0/8", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce t=tmpl-all r=9c0e1f2a3b4c5d6e"
          tags           = { ManagedBy = "ColorTokens", "ct:origin" = "authored", "ct:mode" = "enforce", "ct:template" = "tmpl-all", "ct:rule" = "9c0e1f2a3b4c5d6e" }
        }
        "rds/orders-db/in/tcp/5432/10.20.1.11/32" = {
          security_group = "rds/orders-db", ip_protocol = "tcp", from_port = 5432, to_port = 5432
          cidr_ipv4      = "10.20.1.11/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce t=tmpl-db r=a1b2c3d4e5f60718"
          tags           = { ManagedBy = "ColorTokens", "ct:origin" = "authored", "ct:mode" = "enforce", "ct:template" = "tmpl-db", "ct:rule" = "a1b2c3d4e5f60718" }
        }
      }
      egress_rules = {
        "i-0a1/out/tcp/443/pl-0a1b2c3d" = {
          security_group = "i-0a1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = null, prefix_list_id = "pl-0a1b2c3d", referenced_security_group_id = null
          description    = "ColorTokens authored enforce t=tmpl-saas r=0f1e2d3c4b5a6978"
          tags           = { ManagedBy = "ColorTokens", "ct:origin" = "authored", "ct:mode" = "enforce", "ct:template" = "tmpl-saas", "ct:rule" = "0f1e2d3c4b5a6978" }
        }
      }
      interface_attachments = {
        "i-0a1/eni-0a1"  = { security_group = "i-0a1", network_interface_id = "eni-0a1", slot_limit = 5 }
        "i-0a1/eni-0a1b" = { security_group = "i-0a1", network_interface_id = "eni-0a1b", slot_limit = null }
      }
      directory = {
        "rds/orders-db" = {
          parameter_name  = "/colortokens/v1/rds/orders-db/security-groups"
          handle          = "rds/orders-db"
          security_groups = ["rds/orders-db"]
          tags            = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" }
          slot_limit      = 5
        }
      }
      assets = {
        "asset-web-1"    = { security_group = "i-0a1", attached_by = "pipeline" }
        "asset-orders-1" = { security_group = "rds/orders-db", attached_by = "owner" }
        "asset-batch-1"  = { security_group = null, attached_by = "pipeline" }
      }
      withdrawing = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = { applied_attachments = {} }
  }
}

variables {
  tags = { team = "platform" }
}

run "plans_every_listed_resource" {
  command = plan

  assert {
    condition     = toset(keys(aws_security_group.this)) == toset(["i-0a1", "rds/orders-db"])
    error_message = "one security group per snapshot key"
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 4 && length(aws_vpc_security_group_egress_rule.this) == 1
    error_message = "one rule per snapshot rule"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["i-0a1/in/-1/any/10.0.0.0/8"].from_port == null && aws_vpc_security_group_ingress_rule.this["i-0a1/in/-1/any/10.0.0.0/8"].to_port == null
    error_message = "an all-traffic rule must pass null ports, which AWS requires"
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.this["i-0a1/out/tcp/443/pl-0a1b2c3d"].prefix_list_id == "pl-0a1b2c3d"
    error_message = "a prefix list source must reach the rule"
  }
  assert {
    condition     = toset([for a in aws_network_interface_sg_attachment.this : a.network_interface_id]) == toset(["eni-0a1", "eni-0a1b"])
    error_message = "the instance's group goes on each of its interfaces"
  }
  assert {
    condition     = aws_ssm_parameter.directory["rds/orders-db"].name == "/colortokens/v1/rds/orders-db/security-groups"
    error_message = "the database's directory entry is named by its handle"
  }
  assert {
    condition     = aws_security_group.this["i-0a1"].tags["ManagedBy"] == "ColorTokens" && aws_security_group.this["i-0a1"].tags["team"] == "platform"
    error_message = "a group carries Xshield's tags and the caller's"
  }
  assert {
    condition     = output.summary.rules == 5 && output.summary.attached_by_owner == tolist(["rds/orders-db"])
    error_message = "the summary counts what the plan holds"
  }
}

run "receipt_lists_what_was_created" {
  command = apply

  assert {
    condition     = toset(keys(xshield_enforcement_receipt.this[0].security_groups)) == toset(keys(aws_security_group.this))
    error_message = "the receipt lists every security group, and only those"
  }
  assert {
    condition     = length(xshield_enforcement_receipt.this[0].rules) == 5 && length(xshield_enforcement_receipt.this[0].attachments) == 2
    error_message = "the receipt lists every rule and attachment"
  }
  assert {
    condition     = jsondecode(aws_ssm_parameter.directory["rds/orders-db"].insecure_value).security_group_ids == [aws_security_group.this["rds/orders-db"].id]
    error_message = "the directory gives the database its group's ID"
  }
  assert {
    condition     = jsondecode(aws_ssm_parameter.directory["rds/orders-db"].insecure_value).slot_limit == 5
    error_message = "the directory tells the database's workspace how many groups AWS allows on it"
  }
  assert {
    condition     = output.security_group_ids["asset-batch-1"] == null && output.security_group_ids["asset-web-1"] == aws_security_group.this["i-0a1"].id
    error_message = "each asset maps to its group's ID, or null when it has none"
  }
}

# An instance terminated before discovery told Xshield keeps its attachment in the
# snapshot: the apply attaches what still exists and the receipt leaves the rest out.
run "gone_interface_is_neither_attached_nor_receipted" {
  command = apply

  override_data {
    target = data.aws_network_interfaces.present[0]
    values = { ids = ["eni-0a1"] }
  }

  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-0a1/eni-0a1"])
    error_message = "only the interface that still exists is attached"
  }
  assert {
    condition     = toset(keys(xshield_enforcement_receipt.this[0].attachments)) == toset(["i-0a1/eni-0a1"])
    error_message = "the receipt leaves out the gone interface's attachment"
  }
  assert {
    condition     = toset(keys(xshield_enforcement_receipt.this[0].security_groups)) == toset(keys(aws_security_group.this))
    error_message = "the receipt still lists every group"
  }
}

# An interface that filled up since Xshield last discovered it would make AWS refuse
# the apply, so a new attachment is left off it with a warning, and the receipt
# leaves it out; the rest of the account is still enforced.
run "new_attachment_is_left_off_a_full_interface" {
  command = apply

  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3", "sg-4", "sg-5"], attachment = [{ instance_id = "i-0a1", attachment_id = "eni-attach-1", device_index = 0, network_card_index = 0, instance_owner_id = "123456789012" }] }
  }

  expect_failures = [check.interfaces_have_room]

  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-0a1/eni-0a1b"])
    error_message = "the full interface is left out and the other attached"
  }
  assert {
    condition     = toset(keys(xshield_enforcement_receipt.this[0].attachments)) == toset(["i-0a1/eni-0a1b"])
    error_message = "the receipt leaves out the attachment the interface had no room for"
  }
  assert {
    condition     = local.full_interfaces == { "eni-0a1" = "i-0a1" }
    error_message = "the warning names the interface and its instance"
  }
}

# What the last receipt attached already holds its slot, so a full interface keeps it.
run "applied_attachment_stays_on_a_full_interface" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this[0]
    values = { applied_attachments = { "i-0a1/eni-0a1" = "eni-0a1_sg-0abc" } }
  }

  assert {
    condition     = length(data.aws_network_interface.receiving) == 0 && contains(keys(aws_network_interface_sg_attachment.this), "i-0a1/eni-0a1")
    error_message = "an attachment the last receipt holds is neither read again nor left out"
  }
}

run "new_attachment_goes_on_an_interface_with_room" {
  command = plan

  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-0a1/eni-0a1", "i-0a1/eni-0a1b"]) && length(local.full_interfaces) == 0
    error_message = "two groups and ours fit under a limit of five"
  }
  assert {
    condition     = toset(keys(data.aws_network_interface.receiving)) == toset(["eni-0a1"])
    error_message = "only the interface with a new attachment and a known limit is read"
  }
}

run "refuses_another_accounts_snapshot" {
  command = plan

  variables {
    cloud_account_id = "123456789012"
  }

  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "111122223333" }
  }

  expect_failures = [data.xshield_enforcement_snapshot.this]
}

run "keeps_connector_tags" {
  command = plan

  variables {
    tags = { ManagedBy = "platform-team" }
  }

  expect_failures = [var.tags]
}

run "empty_snapshot_still_reports" {
  command = apply

  override_data {
    target = data.xshield_enforcement_snapshot.this
    values = {
      published             = true
      version               = "v43"
      security_groups       = {}
      ingress_rules         = {}
      egress_rules          = {}
      interface_attachments = {}
      directory             = {}
      assets                = {}
      withdrawing           = []
    }
  }

  assert {
    condition     = length(aws_security_group.this) == 0 && xshield_enforcement_receipt.this[0].snapshot_version == "v43"
    error_message = "moving to Off removes every group and still confirms the version"
  }
}

# At Full control a cohort keeps a moved customer rule, which may name another group.
run "full_control_cohort_rule_names_its_group" {
  command = plan

  override_data {
    target = data.xshield_enforcement_snapshot.this
    values = {
      published = true
      version   = "v44"
      security_groups = {
        "ct-cohort-0123456789abcdef" = {
          name        = "ct-cohort-0123456789abcdef"
          description = "ColorTokens split cohort group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1", "ct:split-group" = "sg-web", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules = {
        "ct-cohort-0123456789abcdef/in/tcp/443/sg-lb" = {
          security_group = "ct-cohort-0123456789abcdef", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = "sg-lb"
          description    = null
          tags           = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
      }
      egress_rules = {}
      interface_attachments = {
        "ct-cohort-0123456789abcdef/eni-legacy" = { security_group = "ct-cohort-0123456789abcdef", network_interface_id = "eni-legacy", slot_limit = null }
      }
      directory   = {}
      assets      = {}
      withdrawing = []
    }
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.this["ct-cohort-0123456789abcdef/in/tcp/443/sg-lb"].referenced_security_group_id == "sg-lb"
    error_message = "a cohort's copy of a rule naming a group must keep that group as its source"
  }
  assert {
    condition     = aws_network_interface_sg_attachment.this["ct-cohort-0123456789abcdef/eni-legacy"].network_interface_id == "eni-legacy"
    error_message = "the cohort goes on the interface of the workload that keeps the rule"
  }
}

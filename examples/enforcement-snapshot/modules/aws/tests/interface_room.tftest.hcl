# terraform test, offline: both providers are mocked. One interface gets two of Xshield's groups in the same
# run, the workload's own group and a cohort group, and the account allows five groups on an interface.

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
    defaults = { ids = ["eni-0a1"] }
  }
  mock_data "aws_network_interface" {
    defaults = { security_groups = ["sg-0customer1", "sg-0customer2"], attachment = [] }
  }
}

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v7"
      security_groups = {
        "i-0a1" = {
          name        = "ct-policy-3f2a9c1d7e4b"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
        "ct-cohort-0example" = {
          name        = "ct-cohort-0example"
          description = "ColorTokens cohort group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:delivery" = "pipeline", "ct:split-group" = "sg-0example", "ct:change-set" = "cs-example" }
        }
      }
      ingress_rules = {}
      egress_rules  = {}
      interface_attachments = {
        "i-0a1/eni-0a1"              = { security_group = "i-0a1", network_interface_id = "eni-0a1", slot_limit = 5 }
        "ct-cohort-0example/eni-0a1" = { security_group = "ct-cohort-0example", network_interface_id = "eni-0a1", slot_limit = 5 }
      }
      directory   = {}
      assets      = { "asset-web-1" = { security_group = "i-0a1", attached_by = "pipeline" } }
      withdrawing = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = { applied_attachments = {}, handover_attachments = {} }
  }
}

run "two_new_groups_go_on_an_interface_with_room_for_both" {
  command = plan

  assert {
    condition     = length(local.full_interfaces) == 0
    error_message = "two groups and two of ours fit under a limit of five"
  }
  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-0a1/eni-0a1", "ct-cohort-0example/eni-0a1"])
    error_message = "both new groups are attached"
  }
}

run "two_new_groups_fill_an_interface_exactly" {
  command = plan

  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3"], attachment = [] }
  }

  assert {
    condition     = length(local.full_interfaces) == 0 && length(aws_network_interface_sg_attachment.this) == 2
    error_message = "three groups and two of ours make five, which the account allows"
  }
}

# One new group would fit and two do not, so neither goes on: a cohort group without the workload's own group, or
# the other way round, is not what Xshield published.
run "two_new_groups_are_both_left_off_an_interface_with_room_for_one" {
  command = plan

  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3", "sg-4"], attachment = [] }
  }

  expect_failures = [check.interfaces_have_room]

  assert {
    condition     = length(aws_network_interface_sg_attachment.this) == 0
    error_message = "neither new group is attached"
  }
}

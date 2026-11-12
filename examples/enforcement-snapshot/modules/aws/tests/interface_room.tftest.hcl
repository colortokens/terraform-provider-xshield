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
      directory_entries           = {}
      assets                      = { "asset-web-1" = { security_group = "i-0a1", attached_by = "pipeline" } }
      withdrawing_security_groups = []
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

# An apply that attached the workload's group and then failed sent no receipt, so the run after it still finds
# the attachment new, with the group already on the interface. The group takes no further room there: counted
# again it would read the interface as full, and the attachment the failed apply made would be removed.
run "a_retry_keeps_the_group_a_failed_apply_already_attached" {
  command = plan

  override_data {
    target = data.aws_security_groups.attaching["i-0a1"]
    values = { ids = ["sg-0ours"] }
  }
  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3", "sg-0ours"], attachment = [] }
  }

  assert {
    condition     = length(local.full_interfaces) == 0
    error_message = "three groups, ours already attached and the cohort group still to add make five, which the account allows"
  }
  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-0a1/eni-0a1", "ct-cohort-0example/eni-0a1"])
    error_message = "the attachment the failed apply made is kept, and the cohort group is attached beside it"
  }
}

run "a_retry_with_both_groups_already_attached_plans_them_again" {
  command = plan

  override_data {
    target = data.aws_security_groups.attaching["i-0a1"]
    values = { ids = ["sg-0ours"] }
  }
  override_data {
    target = data.aws_security_groups.attaching["ct-cohort-0example"]
    values = { ids = ["sg-0cohort"] }
  }
  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3", "sg-0ours", "sg-0cohort"], attachment = [] }
  }

  assert {
    condition     = length(local.full_interfaces) == 0 && length(aws_network_interface_sg_attachment.this) == 2
    error_message = "an interface at its limit with both of ours already on it has nothing more to take"
  }
}

# A group of ours on another interface says nothing about this one, which still has to take it.
run "a_group_that_exists_but_is_not_on_the_interface_still_needs_room" {
  command = plan

  override_data {
    target = data.aws_security_groups.attaching["i-0a1"]
    values = { ids = ["sg-0ours"] }
  }
  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3", "sg-4"], attachment = [] }
  }

  expect_failures = [check.interfaces_have_room]

  assert {
    condition     = length(aws_network_interface_sg_attachment.this) == 0
    error_message = "four groups and two of ours still to add pass five, so neither is attached"
  }
}

# The last receipt lists the workload's own group as attached, so only the cohort group is new. The interface has
# no room for it: the cohort group is left off, and the attachment already applied stays.
run "a_full_interface_keeps_the_group_already_applied_and_leaves_only_the_new_one_off" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this[0]
    values = { applied_attachments = { "i-0a1/eni-0a1" = "eni-0a1_sg-0ours" }, handover_attachments = {} }
  }
  override_data {
    target = data.aws_network_interface.receiving["eni-0a1"]
    values = { security_groups = ["sg-1", "sg-2", "sg-3", "sg-4", "sg-0ours"], attachment = [] }
  }

  expect_failures = [check.interfaces_have_room]

  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-0a1/eni-0a1"])
    error_message = "five groups leave no room for the cohort group, and the group the last apply attached is kept"
  }
}

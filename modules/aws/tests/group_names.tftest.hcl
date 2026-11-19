# terraform test, offline: both providers are mocked. The snapshot names a database's group from the account's security
# group name template, and a group already in the VPC may hold that name.

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
}

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v1"
      security_groups = {
        "rds/orders-db" = {
          name        = "policy-orders-db-3f2a9c1d7e4b"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0a1b2c3d4e5f60718"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:owner" = "3f2a9c1d7e4b5a69", "ct:delivery" = "pipeline", Name = "policy-orders-db-3f2a9c1d7e4b" }
        }
      }
      ingress_rules         = {}
      egress_rules          = {}
      interface_attachments = {}
      directory_entries = {
        "rds/orders-db" = {
          parameter_name  = "/colortokens/v1/rds/orders-db/security-groups"
          handle          = "rds/orders-db"
          security_groups = ["rds/orders-db"]
          tags            = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" }
          slot_limit      = 5
        }
      }
      assets                      = { "asset-orders-1" = { security_group = "rds/orders-db", attached_by = "owner" } }
      withdrawing_security_groups = []
    }
  }
  mock_data "xshield_aws_enforcement_status" {
    defaults = { applied_security_groups = {}, applied_attachments = {}, handover_attachments = {} }
  }
}

run "a_new_group_whose_name_no_group_holds_is_created" {
  command = plan

  assert {
    condition     = keys(data.aws_security_groups.named) == ["rds/orders-db"] && length(data.aws_security_group.name_holder) == 0
    error_message = "the name of a group the last receipt does not hold is looked up once, and nothing holds it"
  }
  assert {
    condition     = aws_security_group.this["rds/orders-db"].name == "policy-orders-db-3f2a9c1d7e4b" && aws_security_group.this["rds/orders-db"].tags["Name"] == "policy-orders-db-3f2a9c1d7e4b"
    error_message = "the group takes the snapshot's name, and its Name tag is that name"
  }
}

run "a_group_that_is_not_xshields_holding_the_name_stops_the_plan" {
  command = plan

  override_data {
    target = data.aws_security_groups.named["rds/orders-db"]
    values = { ids = ["sg-0123456789abcdef0"] }
  }
  override_data {
    target = data.aws_security_group.name_holder["rds/orders-db sg-0123456789abcdef0"]
    values = { id = "sg-0123456789abcdef0", name = "policy-orders-db-3f2a9c1d7e4b", vpc_id = "vpc-0a1b2c3d4e5f60718", tags = { team = "platform" } }
  }

  expect_failures = [data.aws_security_group.name_holder]
}

run "another_workloads_group_of_xshields_holding_the_name_stops_the_plan" {
  command = plan

  override_data {
    target = data.aws_security_groups.named["rds/orders-db"]
    values = { ids = ["sg-0123456789abcdef0"] }
  }
  override_data {
    target = data.aws_security_group.name_holder["rds/orders-db sg-0123456789abcdef0"]
    values = {
      id   = "sg-0123456789abcdef0", name = "policy-orders-db-3f2a9c1d7e4b", vpc_id = "vpc-0a1b2c3d4e5f60718"
      tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:owner" = "9e8d7c6b5a493827" }
    }
  }

  expect_failures = [data.aws_security_group.name_holder]
}

# An apply that created the group and then failed sent no receipt, so the run after it finds the group under its name.
run "xshields_own_group_holding_the_name_is_planned_again" {
  command = plan

  override_data {
    target = data.aws_security_groups.named["rds/orders-db"]
    values = { ids = ["sg-0123456789abcdef0"] }
  }
  override_data {
    target = data.aws_security_group.name_holder["rds/orders-db sg-0123456789abcdef0"]
    values = {
      id   = "sg-0123456789abcdef0", name = "policy-orders-db-3f2a9c1d7e4b", vpc_id = "vpc-0a1b2c3d4e5f60718"
      tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:owner" = "3f2a9c1d7e4b5a69" }
    }
  }

  assert {
    condition     = keys(aws_security_group.this) == ["rds/orders-db"]
    error_message = "the group of Xshield's for this key holds its name, so the plan goes on"
  }
}

# A cohort group carries no ct:owner tag; its change set tells Xshield's cohort groups apart.
run "another_change_sets_cohort_group_holding_the_name_stops_the_plan" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v1"
      security_groups = {
        "ct-cohort-0123456789abcdef" = {
          name        = "ct-cohort-0123456789abcdef"
          description = "ColorTokens split cohort group"
          vpc_id      = "vpc-0a1b2c3d4e5f60718"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-2", "ct:split-group" = "sg-0example", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules               = {}
      egress_rules                = {}
      interface_attachments       = {}
      directory_entries           = {}
      assets                      = {}
      withdrawing_security_groups = []
    }
  }
  override_data {
    target = data.aws_security_groups.named["ct-cohort-0123456789abcdef"]
    values = { ids = ["sg-0123456789abcdef0"] }
  }
  override_data {
    target = data.aws_security_group.name_holder["ct-cohort-0123456789abcdef sg-0123456789abcdef0"]
    values = {
      id   = "sg-0123456789abcdef0", name = "ct-cohort-0123456789abcdef", vpc_id = "vpc-0a1b2c3d4e5f60718"
      tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1", "ct:split-group" = "sg-0example" }
    }
  }

  expect_failures = [data.aws_security_group.name_holder]
}

run "xshields_own_cohort_group_holding_the_name_is_planned_again" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v1"
      security_groups = {
        "ct-cohort-0123456789abcdef" = {
          name        = "ct-cohort-0123456789abcdef"
          description = "ColorTokens split cohort group"
          vpc_id      = "vpc-0a1b2c3d4e5f60718"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-2", "ct:split-group" = "sg-0example", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules               = {}
      egress_rules                = {}
      interface_attachments       = {}
      directory_entries           = {}
      assets                      = {}
      withdrawing_security_groups = []
    }
  }
  override_data {
    target = data.aws_security_groups.named["ct-cohort-0123456789abcdef"]
    values = { ids = ["sg-0123456789abcdef0"] }
  }
  override_data {
    target = data.aws_security_group.name_holder["ct-cohort-0123456789abcdef sg-0123456789abcdef0"]
    values = {
      id   = "sg-0123456789abcdef0", name = "ct-cohort-0123456789abcdef", vpc_id = "vpc-0a1b2c3d4e5f60718"
      tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-2", "ct:split-group" = "sg-0example" }
    }
  }

  assert {
    condition     = keys(aws_security_group.this) == ["ct-cohort-0123456789abcdef"]
    error_message = "Xshield's cohort group of this change set holds its name, so the plan goes on"
  }
}

# The filter reads * and ? as wildcards, so a lookup can find a group under another name.
run "a_group_found_under_another_name_holds_none" {
  command = plan

  override_data {
    target = data.aws_security_groups.named["rds/orders-db"]
    values = { ids = ["sg-0123456789abcdef0"] }
  }
  override_data {
    target = data.aws_security_group.name_holder["rds/orders-db sg-0123456789abcdef0"]
    values = { id = "sg-0123456789abcdef0", name = "policy-orders-db-3f2a9c1d7e4b-old", vpc_id = "vpc-0a1b2c3d4e5f60718", tags = {} }
  }

  assert {
    condition     = keys(aws_security_group.this) == ["rds/orders-db"]
    error_message = "a group under another name does not stop the plan"
  }
}

run "a_group_the_last_receipt_holds_is_not_looked_up" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this[0]
    values = { applied_security_groups = { "rds/orders-db" = "sg-0123456789abcdef0" }, applied_attachments = {}, handover_attachments = {} }
  }

  assert {
    condition     = length(data.aws_security_groups.named) == 0 && length(data.aws_security_group.name_holder) == 0
    error_message = "a group the last receipt holds is already in place under its name, so its name is not looked up"
  }
}

# terraform test, offline: both providers are mocked. Xshield has taken the group's broad HTTPS rule out. Each run
# says which resources Xshield does not enforce on carry the group without anyone having acknowledged them.

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
      egress_rules               = {}
      revoked_rules              = ["ingress/https_all"]
      pending_rules              = []
      reopening_rules            = []
      undeclared_pending_rules   = []
      undeclared_restoring_rules = []
      unacknowledged_carriers    = []
    }
  }
}

variables {
  xshield_changes   = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
  vpc_id            = "vpc-0example"
  group_name        = "web"
  security_group_id = "sg-0example"

  ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
}

run "no_unacknowledged_carrier_plans_without_a_warning" {
  command = plan

  variables {
    fail_on_unacknowledged_carriers = true
  }

  assert {
    condition     = length(output.unacknowledged_carriers) == 0
    error_message = "a group Xshield names no unacknowledged carrier for must list none"
  }
  assert {
    condition     = local.unacknowledged_carriers_message == ""
    error_message = "a group with no unacknowledged carrier must have nothing to warn about"
  }
}

run "a_group_no_change_applies_to_lists_no_carrier" {
  command = plan

  variables {
    xshield_changes                 = { cloud_account_id = "111111111111", region = "us-east-1", groups = {} }
    fail_on_unacknowledged_carriers = true
  }

  assert {
    condition     = length(output.unacknowledged_carriers) == 0
    error_message = "a group no change applies to reads nothing from Xshield and lists no carrier"
  }
}

run "unacknowledged_carriers_warn_and_are_named" {
  command = plan

  override_data {
    target = data.xshield_aws_security_group_rules.this
    values = {
      ingress_rules = {
        ssh_office = {
          ip_protocol    = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      revoked_rules           = ["ingress/https_all"]
      unacknowledged_carriers = ["lb-public", "vpce-s3"]
    }
  }

  expect_failures = [check.unacknowledged_carriers]

  assert {
    condition     = output.unacknowledged_carriers == tolist(["lb-public", "vpce-s3"])
    error_message = "the output must list each carrier Xshield names"
  }
  assert {
    condition = alltrue([
      strcontains(local.unacknowledged_carriers_message, "lb-public, vpce-s3"),
      strcontains(local.unacknowledged_carriers_message, "group web is also carried by"),
      strcontains(local.unacknowledged_carriers_message, "lose the rules this apply takes out"),
      strcontains(local.unacknowledged_carriers_message, "Deploy the change again in Xshield"),
      strcontains(local.unacknowledged_carriers_message, "own security group"),
    ])
    error_message = "the warning must name the group and every carrier, say what they lose, and say what to do: ${local.unacknowledged_carriers_message}"
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["ssh_office"])
    error_message = "a warning must not stop the plan taking the rule out"
  }
}

run "unacknowledged_carriers_fail_the_plan_when_asked_to" {
  command = plan

  variables {
    fail_on_unacknowledged_carriers = true
  }

  override_data {
    target = data.xshield_aws_security_group_rules.this
    values = {
      ingress_rules = {
        ssh_office = {
          ip_protocol    = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      revoked_rules           = ["ingress/https_all"]
      unacknowledged_carriers = ["lb-public"]
    }
  }

  expect_failures = [aws_vpc_security_group_ingress_rule.this, terraform_data.xshield_routed, check.unacknowledged_carriers]
}

# Every rule taken out leaves the module no rule resource, and the record still stops the plan.
run "unacknowledged_carriers_fail_the_plan_of_a_group_left_with_no_rule" {
  command = plan

  variables {
    fail_on_unacknowledged_carriers = true
    ingress_rules                   = { https_all = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" } }
  }

  override_data {
    target = data.xshield_aws_security_group_rules.this
    values = { ingress_rules = {}, revoked_rules = ["ingress/https_all"], unacknowledged_carriers = ["lb-public"] }
  }

  expect_failures = [terraform_data.xshield_routed, check.unacknowledged_carriers]
}

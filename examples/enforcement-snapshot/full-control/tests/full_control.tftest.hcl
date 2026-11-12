# terraform test, offline: both providers are mocked. Xshield lists a change for
# the group web in the workspace's VPC, and whenever the workspace reads the
# group's rules from Xshield, the mock answers as Xshield does once it has taken
# HTTPS from anywhere out of the group.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id = "sg-0a1b2c3d4e5f60718"
    }
  }
}

mock_provider "xshield" {
  mock_data "xshield_aws_security_group_changes" {
    defaults = {
      published = true
      version   = "v7"
      groups    = { web = ["vpc-0a1b2c3d4e5f60718"] }
    }
  }

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
        all = {
          ip_protocol    = "-1", from_port = null, to_port = null, cidr_ipv4 = "0.0.0.0/0", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      revoked = ["ingress/https_all"]
      pending = []
    }
  }
}

variables {
  vpc_id = "vpc-0a1b2c3d4e5f60718"
}

run "the_rule_xshield_takes_out_leaves_the_workspaces_plan" {
  assert {
    condition     = data.xshield_aws_security_group_changes.this.cloud_account_id == "123456789012" && data.xshield_aws_security_group_changes.this.region == "us-east-1"
    error_message = "the workspace asks Xshield about the account and region its AWS provider is configured for"
  }
  assert {
    condition     = module.web_rules.ingress_keys == tolist(["ssh_office"])
    error_message = "the rule Xshield took out is no longer declared, and the rule it kept is"
  }
  assert {
    condition     = module.web_rules.egress_keys == tolist(["all"])
    error_message = "a rule no change narrows stays declared"
  }
  assert {
    condition     = output.xshield_review == tolist(["Group web: rule ingress/https_all (TCP 443 from 0.0.0.0/0) is taken out by Xshield."])
    error_message = "the output says which rule Xshield took out"
  }
}

run "a_group_no_change_applies_to_plans_as_the_team_declares_it" {
  override_data {
    target = data.xshield_aws_security_group_changes.this
    values = { published = true, version = "v7", groups = {} }
  }

  assert {
    condition     = module.web_rules.ingress_keys == tolist(["https_all", "ssh_office"]) && module.web_rules.egress_keys == tolist(["all"])
    error_message = "a group Xshield lists no change for declares every rule the team wrote"
  }
  assert {
    condition     = length(output.xshield_review) == 0
    error_message = "the output is empty while no change applies to the group"
  }
}

# A group is found by its name and its VPC, so a change for a group called web
# in another VPC does not touch this one.
run "a_change_for_the_same_name_in_another_vpc_leaves_the_group_as_declared" {
  variables {
    vpc_id = "vpc-0f1e2d3c4b5a69788"
  }

  assert {
    condition     = module.web_rules.ingress_keys == tolist(["https_all", "ssh_office"]) && module.web_rules.egress_keys == tolist(["all"])
    error_message = "a change for another VPC's group of the same name leaves every declared rule in place"
  }
}

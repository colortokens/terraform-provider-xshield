# terraform test, offline: both providers are mocked, and a mocked provider
# imports nothing, so each import's target is overridden with what AWS would
# return for the ID its import names. What the run proves is the wiring of
# adopt.tf to main.tf: the plan is made only when every import names a resource
# the configuration declares. The overrides are set while planning, which needs
# Terraform 1.11 or later to run this file.

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
}

mock_provider "xshield" {
  mock_data "xshield_aws_security_group_changes" {
    defaults = {
      published = true
      version   = "v7"
      groups    = {}
    }
  }
}

override_resource {
  target          = aws_security_group.web
  override_during = plan
  values          = { id = "sg-0a1b2c3d4e5f60100" }
}

override_resource {
  target          = aws_security_group.app
  override_during = plan
  values          = { id = "sg-0a1b2c3d4e5f60200" }
}

override_resource {
  target          = aws_security_group.batch
  override_during = plan
  values          = { id = "sg-0a1b2c3d4e5f60300" }
}

override_resource {
  target = module.web_rules.aws_vpc_security_group_ingress_rule.this["https_all"]
  values = { id = "sgr-0a1b2c3d4e5f60101" }
}

override_resource {
  target = module.web_rules.aws_vpc_security_group_ingress_rule.this["ssh_office"]
  values = { id = "sgr-0a1b2c3d4e5f60102" }
}

override_resource {
  target = module.web_rules.aws_vpc_security_group_egress_rule.this["all"]
  values = { id = "sgr-0a1b2c3d4e5f60103" }
}

override_resource {
  target = module.app_rules.aws_vpc_security_group_ingress_rule.this["from_web"]
  values = { id = "sgr-0a1b2c3d4e5f60201" }
}

override_resource {
  target = module.app_rules.aws_vpc_security_group_ingress_rule.this["ssh_office_a"]
  values = { id = "sgr-0a1b2c3d4e5f60202" }
}

override_resource {
  target = module.app_rules.aws_vpc_security_group_ingress_rule.this["ssh_office_b"]
  values = { id = "sgr-0a1b2c3d4e5f60203" }
}

override_resource {
  target = module.app_rules.aws_vpc_security_group_egress_rule.this["s3"]
  values = { id = "sgr-0a1b2c3d4e5f60204" }
}

override_resource {
  target = module.batch_rules.aws_vpc_security_group_ingress_rule.this["all_from_vpc"]
  values = { id = "sgr-0a1b2c3d4e5f60301" }
}

override_resource {
  target = module.batch_rules.aws_vpc_security_group_egress_rule.this["all"]
  values = { id = "sgr-0a1b2c3d4e5f60302" }
}

variables {
  vpc_id            = "vpc-0a1b2c3d4e5f60718"
  s3_prefix_list_id = "pl-0a1b2c3d4e5f60400"
}

run "every_rule_already_in_aws_is_declared_under_the_key_its_import_names" {
  command = plan

  assert {
    condition     = module.web_rules.ingress_keys == tolist(["https_all", "ssh_office"]) && module.web_rules.egress_keys == tolist(["all"])
    error_message = "the web group declares each rule its inline blocks held"
  }
  assert {
    condition     = module.app_rules.ingress_keys == tolist(["from_web", "ssh_office_a", "ssh_office_b"]) && module.app_rules.egress_keys == tolist(["s3"])
    error_message = "the app group declares one rule for each rule in AWS, so the resource with two ranges is two entries"
  }
  assert {
    condition     = module.batch_rules.ingress_keys == tolist(["all_from_vpc"]) && module.batch_rules.egress_keys == tolist(["all"])
    error_message = "the batch group declares the rules it was given by hand"
  }
  assert {
    condition     = length(output.xshield_review) == 0
    error_message = "no approved change applies to the groups while they are adopted"
  }
}

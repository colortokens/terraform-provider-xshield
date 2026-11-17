# terraform test, offline: both providers are mocked, and set up as recovery.tftest.hcl says. A key in skipped_imports
# has no override here, and a mock provider refuses any import without one, so a run fails if a skipped key is imported.
# A plan here shows whether a key nobody skipped is imported only for a group, by its ID: the runs check that each such
# key stays among the imports.

mock_provider "aws" {
  # What the apply creates has its ID at plan, as AWS gives it at apply. These defaults name no address, so they let no
  # import through.
  mock_resource "aws_security_group" {
    override_during = plan
    defaults        = { id = "sg-0123456789abcdef0" }
  }
  mock_resource "aws_vpc_security_group_ingress_rule" {
    override_during = plan
    defaults        = { security_group_rule_id = "sgr-0123456789abcdef0" }
  }
  mock_resource "aws_vpc_security_group_egress_rule" {
    override_during = plan
    defaults        = { security_group_rule_id = "sgr-0123456789abcdef0" }
  }
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
    defaults = { ids = ["eni-1", "eni-2"] }
  }
  mock_data "aws_network_interface" {
    defaults = { security_groups = ["sg-0customer"], attachment = [] }
  }
  mock_data "aws_network_acls" {
    defaults = { ids = ["acl-0a1b"] }
  }
}

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v1"
      security_groups = {
        "i-1" = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "i-2" = { name = "ct-policy-0000000000a2", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
      }
      ingress_rules = {
        "i-1/in/tcp/443/0.0.0.0/0" = {
          security_group = "i-1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "0.0.0.0/0", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]"
          tags           = { ManagedBy = "ColorTokens" }
        }
        "i-2/in/tcp/22/203.0.113.7/32" = {
          security_group = "i-2", ip_protocol = "tcp", from_port = 22, to_port = 22
          cidr_ipv4      = "203.0.113.7/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]"
          tags           = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules = {
        "i-1/out/tcp/443/0.0.0.0/0" = {
          security_group = "i-1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "0.0.0.0/0", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]"
          tags           = { ManagedBy = "ColorTokens" }
        }
        "i-2/out/tcp/5432/203.0.113.7/32" = {
          security_group = "i-2", ip_protocol = "tcp", from_port = 5432, to_port = 5432
          cidr_ipv4      = "203.0.113.7/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]"
          tags           = { ManagedBy = "ColorTokens" }
        }
      }
      interface_attachments = {
        "i-1/eni-1" = { security_group = "i-1", network_interface_id = "eni-1", slot_limit = 5 }
        "i-2/eni-2" = { security_group = "i-2", network_interface_id = "eni-2", slot_limit = 5 }
      }
      directory_entries = {}
      assets            = { "a-1" = { security_group = "i-1", attached_by = "pipeline" }, "a-2" = { security_group = "i-2", attached_by = "pipeline" } }
      network_acl_entries = {
        "acl-0a1b/in/203.0.113.7/32"  = { network_acl_id = "acl-0a1b", egress = false, rule_number = 50, cidr_ipv4 = "203.0.113.7/32", cidr_ipv6 = null }
        "acl-0a1b/out/203.0.113.7/32" = { network_acl_id = "acl-0a1b", egress = true, rule_number = 50, cidr_ipv4 = "203.0.113.7/32", cidr_ipv6 = null }
      }
      withdrawing_security_groups = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = {
      applied_version         = "v1"
      applied_security_groups = { "i-1" = "sg-00000000000000001", "i-2" = "sg-00000000000000002" }
      applied_rules = {
        "i-1/in/tcp/443/0.0.0.0/0"        = "sgr-0abc"
        "i-2/in/tcp/22/203.0.113.7/32"    = "sgr-0123456789abcdef0"
        "i-1/out/tcp/443/0.0.0.0/0"       = "sgr-0abd"
        "i-2/out/tcp/5432/203.0.113.7/32" = "sgr-0abe"
      }
      applied_attachments = { "i-1/eni-1" = "eni-1_sg-00000000000000001", "i-2/eni-2" = "eni-2_sg-00000000000000002" }
      applied_network_acl_entries = {
        "acl-0a1b/in/203.0.113.7/32"  = "acl-0a1b:50:-1:false"
        "acl-0a1b/out/203.0.113.7/32" = "acl-0a1b:50:-1:true"
      }
      handover_attachments = {}
    }
  }
}

override_resource {
  target = module.xshield_enforcement.aws_security_group.this["i-1"]
  values = { id = "sg-00000000000000001" }
}
override_resource {
  target = module.xshield_enforcement.aws_vpc_security_group_rules_exclusive.this["i-1"]
  values = { id = "sg-00000000000000001" }
}
override_resource {
  target = module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this["i-1/in/tcp/443/0.0.0.0/0"]
  values = { id = "sgr-0abc", security_group_rule_id = "sgr-0abc" }
}
override_resource {
  target = module.xshield_enforcement.aws_vpc_security_group_egress_rule.this["i-1/out/tcp/443/0.0.0.0/0"]
  values = { id = "sgr-0abd", security_group_rule_id = "sgr-0abd" }
}
override_resource {
  target = module.xshield_enforcement.aws_network_interface_sg_attachment.this["i-1/eni-1"]
  values = { id = "sg-00000000000000001_eni-1" }
}
override_resource {
  target = module.xshield_enforcement.aws_network_acl_rule.this["acl-0a1b/out/203.0.113.7/32"]
  values = { id = "nacl-1950887271" }
}
override_resource {
  target = module.xshield_enforcement.xshield_enforcement_receipt.this[0]
  values = { id = "receipt-1" }
}

variables {
  region               = "us-east-1"
  enforcement_role_arn = "arn:aws:iam::123456789012:role/xshield-enforcement"
}

# Each kind's key deleted outside Terraform since the last receipt, or an entry whose receipted number AWS now gives to
# another entry, is left out of the imports and stays declared, so the apply creates it again.
run "a_skipped_key_of_each_kind_is_not_imported_and_stays_declared" {
  command = plan

  variables {
    skipped_imports = {
      security_groups     = ["i-2"]
      rules               = ["i-2/in/tcp/22/203.0.113.7/32", "i-2/out/tcp/5432/203.0.113.7/32"]
      attachments         = ["i-2/eni-2"]
      network_acl_entries = ["acl-0a1b/in/203.0.113.7/32"]
    }
  }

  assert {
    condition     = keys(local.recovered_security_groups) == ["i-1"] && keys(local.recovered_rules) == ["i-1/in/tcp/443/0.0.0.0/0", "i-1/out/tcp/443/0.0.0.0/0"] && keys(local.recovered_attachments) == ["i-1/eni-1"] && keys(local.recovered_network_acl_entries) == ["acl-0a1b/out/203.0.113.7/32"]
    error_message = "a skipped key is left in the imports, or a key nobody skipped is left out"
  }

  # A group the apply creates has the mock's default ID at plan; one imported has the receipted one.
  assert {
    condition     = module.xshield_enforcement.security_group_ids["a-1"] == "sg-00000000000000001"
    error_message = "the group nobody skipped is not imported"
  }

  assert {
    condition     = module.xshield_enforcement.summary.network_acl_entries == 2 && module.xshield_enforcement.attachment_keys == ["i-1/eni-1", "i-2/eni-2"]
    error_message = "a skipped attachment or network ACL entry is no longer declared"
  }
}

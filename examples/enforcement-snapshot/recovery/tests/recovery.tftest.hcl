# terraform test, offline: both providers are mocked. recovery.tf is a file for the enforcement workspace, so it is
# tested in one: copy ../enforcement/main.tf, recovery.tf and this tests directory into an empty directory beside
# recovery/, and run terraform init and terraform test there.

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
      ingress_rules = {}
      egress_rules  = {}
      interface_attachments = {
        "i-1/eni-1" = { security_group = "i-1", network_interface_id = "eni-1", slot_limit = 5 }
        "i-2/eni-2" = { security_group = "i-2", network_interface_id = "eni-2", slot_limit = 5 }
      }
      directory_entries = {}
      assets            = { "a-1" = { security_group = "i-1", attached_by = "pipeline" }, "a-2" = { security_group = "i-2", attached_by = "pipeline" } }
      network_acl_entries = {
        "acl-0a1b/in/203.0.113.7/32" = { network_acl_id = "acl-0a1b", egress = false, rule_number = 50, cidr_ipv4 = "203.0.113.7/32", cidr_ipv6 = null }
      }
      withdrawing_security_groups = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = {
      applied_version         = "v1"
      applied_security_groups = { "i-1" = "sg-00000000000000001", "i-2" = "sg-00000000000000002" }
      applied_rules           = {}
      applied_attachments     = { "i-1/eni-1" = "eni-1_sg-00000000000000001", "i-2/eni-2" = "eni-2_sg-00000000000000002" }
      applied_network_acl_entries = {
        "acl-0a1b/in/203.0.113.7/32"  = "acl-0a1b:50:-1:false"
        "acl-0a1b/in/198.51.100.9/32" = "acl-0a1b:52:-1:false"
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
  target = module.xshield_enforcement.aws_security_group.this["i-2"]
  values = { id = "sg-00000000000000002" }
}
override_resource {
  target = module.xshield_enforcement.aws_vpc_security_group_rules_exclusive.this["i-1"]
  values = { id = "sg-00000000000000001" }
}
override_resource {
  target = module.xshield_enforcement.aws_vpc_security_group_rules_exclusive.this["i-2"]
  values = { id = "sg-00000000000000002" }
}
override_resource {
  target = module.xshield_enforcement.aws_network_interface_sg_attachment.this["i-1/eni-1"]
  values = { id = "sg-00000000000000001_eni-1" }
}
override_resource {
  target = module.xshield_enforcement.aws_network_interface_sg_attachment.this["i-2/eni-2"]
  values = { id = "sg-00000000000000002_eni-2" }
}
override_resource {
  target = module.xshield_enforcement.aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"]
  values = { id = "nacl-1950887270" }
}
override_resource {
  target = module.xshield_enforcement.xshield_enforcement_receipt.this[0]
  values = { id = "receipt-1" }
}

variables {
  region               = "us-east-1"
  enforcement_role_arn = "arn:aws:iam::123456789012:role/xshield-enforcement"
}

# A receipt that names an entry the pinned version does not hold imports only those it does, or the plan stops.
run "each_receipted_network_acl_entry_of_the_version_is_imported" {
  command = plan

  assert {
    condition     = module.xshield_enforcement.summary.network_acl_entries == 1
    error_message = "the version's network ACL entry is declared, so its import has a configuration"
  }
}

run "every_receipted_interface_still_exists" {
  command = plan

  assert {
    condition     = module.xshield_enforcement.attachment_keys == ["i-1/eni-1", "i-2/eni-2"]
    error_message = "both receipted attachments are declared and imported"
  }
}

# The plan must still be made: an import block with no configuration behind it stops it.
run "one_receipted_instance_was_terminated_since_the_last_receipt" {
  command = plan

  override_data {
    target = module.xshield_enforcement.data.aws_network_interfaces.present[0]
    values = { ids = ["eni-1"] }
  }

  assert {
    condition     = module.xshield_enforcement.attachment_keys == ["i-1/eni-1"]
    error_message = "only the attachment whose interface still exists is declared and imported"
  }
}

# The module declares no entry the version it plans no longer holds, so the import of one would have no configuration.
run "a_receipted_network_acl_entry_the_module_does_not_declare_is_not_imported" {
  command = plan

  override_data {
    target = module.xshield_enforcement.data.xshield_aws_enforcement_snapshot.this
    values = {
      cloud_account_id = "123456789012"
      region           = "us-east-1"
      published        = true
      version          = "v2"
      security_groups = {
        "i-1" = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "i-2" = { name = "ct-policy-0000000000a2", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
      }
      ingress_rules = {}
      egress_rules  = {}
      interface_attachments = {
        "i-1/eni-1" = { security_group = "i-1", network_interface_id = "eni-1", slot_limit = 5 }
        "i-2/eni-2" = { security_group = "i-2", network_interface_id = "eni-2", slot_limit = 5 }
      }
      directory_entries           = {}
      assets                      = { "a-1" = { security_group = "i-1", attached_by = "pipeline" }, "a-2" = { security_group = "i-2", attached_by = "pipeline" } }
      network_acl_entries         = {}
      withdrawing_security_groups = []
    }
  }

  assert {
    condition     = module.xshield_enforcement.summary.network_acl_entries == 0
    error_message = "the module declares no network ACL entry, so none is imported"
  }
}

# A key left out of the imports, as when AWS holds another entry at its receipted number, keeps its entry declared,
# to be created at that number.
run "a_skipped_network_acl_entry_is_still_declared" {
  command = plan

  variables {
    skipped_network_acl_entries = ["acl-0a1b/in/203.0.113.7/32"]
  }

  assert {
    condition     = module.xshield_enforcement.summary.network_acl_entries == 1
    error_message = "the skipped entry is still declared, to be created at its receipted number"
  }
}

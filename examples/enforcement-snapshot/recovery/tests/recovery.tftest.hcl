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
      directory   = {}
      assets      = { "a-1" = { security_group = "i-1", attached_by = "pipeline" }, "a-2" = { security_group = "i-2", attached_by = "pipeline" } }
      withdrawing = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = {
      applied_version         = "v1"
      applied_security_groups = { "i-1" = "sg-00000000000000001", "i-2" = "sg-00000000000000002" }
      applied_rules           = {}
      applied_attachments     = { "i-1/eni-1" = "eni-1_sg-00000000000000001", "i-2/eni-2" = "eni-2_sg-00000000000000002" }
      handover_attachments    = {}
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
  target = module.xshield_enforcement.aws_network_interface_sg_attachment.this["i-1/eni-1"]
  values = { id = "sg-00000000000000001_eni-1" }
}
override_resource {
  target = module.xshield_enforcement.aws_network_interface_sg_attachment.this["i-2/eni-2"]
  values = { id = "sg-00000000000000002_eni-2" }
}
override_resource {
  target = module.xshield_enforcement.xshield_enforcement_receipt.this[0]
  values = { id = "receipt-1" }
}

variables {
  region               = "us-east-1"
  enforcement_role_arn = "arn:aws:iam::123456789012:role/xshield-enforcement"
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

# terraform test, offline: both providers are mocked, and each create and destroy runs a local-exec that logs it.
# The first apply after upgrading from a module version without create_before_destroy on the attachments. Copy
# modules/aws/*.tf, apply-order/apply_order_override.tf and this tests directory into an empty directory, and into its
# previous/ subdirectory the *.tf of the version upgraded from and apply_order_override.tf; run terraform init and
# terraform test there. Delete apply-order.log before running the test again.
#
# Terraform orders the removal of an attachment the version drops by what the state recorded at the last apply. An
# apply of the upgraded module, refresh-only or one that drops nothing, records the new order; without it, the first
# apply after the upgrade detaches cohort group c1 before it attaches c2.

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
    defaults = { ids = ["eni-1"] }
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
        "i-1"                  = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline", "ct:owner" = "asset-1" } }
        "ct-cohort-00000000c1" = { name = "ct-cohort-00000000c1", description = "ColorTokens cohort group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline", "ct:kind" = "cohort", "ct:change-set" = "cs-1" } }
      }
      ingress_rules = {
        "ct-cohort-00000000c1/in/tcp/22/10.0.0.0/8" = {
          security_group = "ct-cohort-00000000c1", ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens", tags = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules = {}
      interface_attachments = {
        "i-1/eni-1"                  = { security_group = "i-1", network_interface_id = "eni-1", slot_limit = 5 }
        "ct-cohort-00000000c1/eni-1" = { security_group = "ct-cohort-00000000c1", network_interface_id = "eni-1", slot_limit = 5 }
      }
      directory_entries           = {}
      assets                      = { "asset-1" = { security_group = "i-1", attached_by = "pipeline" } }
      withdrawing_security_groups = []
      network_acl_entries         = {}
    }
  }
  mock_data "xshield_aws_enforcement_status" {
    defaults = { applied_attachments = {}, handover_attachments = {}, applied_security_groups = {} }
  }
}

run "the_first_cohort_is_attached" {
  command   = apply
  state_key = "account"
  module {
    source = "./previous"
  }

  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-1/eni-1", "ct-cohort-00000000c1/eni-1"])
    error_message = "eni-1 carries the workload's group and the first cohort group"
  }
}

run "the_upgraded_module_records_the_new_order" {
  command   = apply
  state_key = "account"

  plan_options {
    mode = refresh-only
  }
}

run "a_superseding_cohort_is_attached_before_the_old_one_comes_off" {
  command   = apply
  state_key = "account"

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v2"
      security_groups = {
        "i-1"                  = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline", "ct:owner" = "asset-1" } }
        "ct-cohort-00000000c2" = { name = "ct-cohort-00000000c2", description = "ColorTokens cohort group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline", "ct:kind" = "cohort", "ct:change-set" = "cs-2" } }
      }
      ingress_rules = {
        "ct-cohort-00000000c2/in/tcp/22/10.0.0.0/8" = {
          security_group = "ct-cohort-00000000c2", ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens", tags = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules = {}
      interface_attachments = {
        "i-1/eni-1"                  = { security_group = "i-1", network_interface_id = "eni-1", slot_limit = 5 }
        "ct-cohort-00000000c2/eni-1" = { security_group = "ct-cohort-00000000c2", network_interface_id = "eni-1", slot_limit = 5 }
      }
      directory_entries           = {}
      assets                      = { "asset-1" = { security_group = "i-1", attached_by = "pipeline" } }
      withdrawing_security_groups = []
      network_acl_entries         = {}
    }
  }

  assert {
    condition     = toset(keys(aws_network_interface_sg_attachment.this)) == toset(["i-1/eni-1", "ct-cohort-00000000c2/eni-1"])
    error_message = "eni-1 carries the workload's group and the superseding cohort group"
  }
  assert {
    condition     = toset(keys(xshield_aws_enforcement_receipt.this[0].attachments)) == toset(["i-1/eni-1", "ct-cohort-00000000c2/eni-1"])
    error_message = "the receipt lists the attachments that remain, not the one the apply takes off after it"
  }
  assert {
    condition = alltrue([for created in [
      "create aws_security_group ${aws_security_group.this["ct-cohort-00000000c2"].name}",
      "create aws_vpc_security_group_ingress_rule ct-cohort-00000000c2/in/tcp/22/10.0.0.0/8",
      "create aws_network_interface_sg_attachment ct-cohort-00000000c2/eni-1",
      ] : contains(split("\n", file("apply-order.log")), created) && (
      index(split("\n", file("apply-order.log")), created) < index(split("\n", file("apply-order.log")), "destroy aws_network_interface_sg_attachment ct-cohort-00000000c1/eni-1")
    )])
    error_message = "c1 came off eni-1 before c2, its rule and its attachment were in place:\n${file("apply-order.log")}"
  }
}

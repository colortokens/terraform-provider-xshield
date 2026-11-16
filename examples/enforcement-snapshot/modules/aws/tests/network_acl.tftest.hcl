# terraform test, offline: the snapshot blocks two addresses of the malicious IP block template on the network ACL
# in front of one instance, one inbound over IPv4 and one outbound over IPv6.

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
}

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v42"
      security_groups = {
        "i-0a1" = {
          name        = "ct-policy-3f2a9c1d7e4b"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules         = {}
      egress_rules          = {}
      interface_attachments = {}
      directory_entries     = {}
      assets                = { "asset-web-1" = { security_group = "i-0a1", attached_by = "pipeline" } }
      network_acl_entries = {
        "acl-0a1b/in/203.0.113.7/32" = {
          network_acl_id = "acl-0a1b", egress = false, rule_number = 50, cidr_ipv4 = "203.0.113.7/32", cidr_ipv6 = null
        }
        "acl-0a1b/out/2001:db8::7/128" = {
          network_acl_id = "acl-0a1b", egress = true, rule_number = 98, cidr_ipv4 = null, cidr_ipv6 = "2001:db8::7/128"
        }
      }
      withdrawing_security_groups = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = { applied_attachments = {}, handover_attachments = {} }
  }
}

run "denies_each_listed_address_on_its_network_acl" {
  command = plan

  assert {
    condition     = toset(keys(aws_network_acl_rule.this)) == toset(["acl-0a1b/in/203.0.113.7/32", "acl-0a1b/out/2001:db8::7/128"])
    error_message = "one network ACL entry per snapshot key"
  }
  assert {
    condition     = alltrue([for entry in values(aws_network_acl_rule.this) : entry.rule_action == "deny" && entry.protocol == "-1" && entry.network_acl_id == "acl-0a1b"])
    error_message = "each entry denies all traffic on the network ACL the snapshot names"
  }
  assert {
    condition = (
      aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"].egress == false &&
      aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"].rule_number == 50 &&
      aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"].cidr_block == "203.0.113.7/32" &&
      aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"].ipv6_cidr_block == null
    )
    error_message = "the inbound IPv4 entry takes the snapshot's direction, number and address"
  }
  assert {
    condition = (
      aws_network_acl_rule.this["acl-0a1b/out/2001:db8::7/128"].egress == true &&
      aws_network_acl_rule.this["acl-0a1b/out/2001:db8::7/128"].rule_number == 98 &&
      aws_network_acl_rule.this["acl-0a1b/out/2001:db8::7/128"].ipv6_cidr_block == "2001:db8::7/128" &&
      aws_network_acl_rule.this["acl-0a1b/out/2001:db8::7/128"].cidr_block == null
    )
    error_message = "the outbound IPv6 entry takes the snapshot's direction, number and address"
  }
  assert {
    condition = xshield_enforcement_receipt.this[0].network_acl_entries == tomap({
      "acl-0a1b/in/203.0.113.7/32"   = "acl-0a1b:50:-1:false"
      "acl-0a1b/out/2001:db8::7/128" = "acl-0a1b:98:-1:true"
    })
    error_message = "the receipt names each entry by its import ID, which Xshield checks against the snapshot's"
  }
  assert {
    condition     = output.summary.network_acl_entries == 2
    error_message = "the summary counts the network ACL entries"
  }
  assert {
    condition = (
      contains(output.review, "Network ACL acl-0a1b denies all inbound traffic from 203.0.113.7/32, which the malicious IP block template blocks.") &&
      contains(output.review, "Network ACL acl-0a1b denies all outbound traffic to 2001:db8::7/128, which the malicious IP block template blocks.") &&
      output.review[length(output.review) - 1] == "Version v42 holds 1 group, 0 rules, 0 interface attachments and 2 network ACL entries for 123456789012/us-east-1."
    )
    error_message = "the review says what each network ACL blocks and counts its entries"
  }
}

run "sends_no_network_acl_entry_without_one" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      security_groups = {
        "i-0a1" = {
          name        = "ct-policy-3f2a9c1d7e4b"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0abc"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules               = {}
      egress_rules                = {}
      interface_attachments       = {}
      directory_entries           = {}
      assets                      = {}
      network_acl_entries         = {}
      withdrawing_security_groups = []
    }
  }

  assert {
    condition     = length(aws_network_acl_rule.this) == 0
    error_message = "no entry without one in the snapshot"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].network_acl_entries == null
    error_message = "a receipt without network ACL entries leaves them null, as a receipt sent before them holds, so upgrading plans no change"
  }
  assert {
    condition     = output.review[length(output.review) - 1] == "Version v43 holds 1 group, 0 rules and 0 interface attachments for 123456789012/us-east-1."
    error_message = "the review's count reads as before for a version without network ACL entries"
  }
}

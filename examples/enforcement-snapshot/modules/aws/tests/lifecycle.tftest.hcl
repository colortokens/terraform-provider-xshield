# terraform test, offline: one workspace's state carried through the life of an
# account, from nothing published to Off. Each run overrides the snapshot with
# the version Xshield would serve at that point, and later runs compare IDs with
# earlier ones, so a group that should survive is shown not to be replaced.

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
      published             = false
      version               = null
      security_groups       = {}
      ingress_rules         = {}
      egress_rules          = {}
      interface_attachments = {}
      directory             = {}
      assets                = {}
      withdrawing           = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = { applied_attachments = {}, handover_attachments = {} }
  }
}

run "nothing_published_creates_nothing" {
  command = apply

  assert {
    condition = alltrue([
      length(aws_security_group.this) == 0,
      length(aws_vpc_security_group_ingress_rule.this) == 0,
      length(aws_vpc_security_group_egress_rule.this) == 0,
      length(aws_network_interface_sg_attachment.this) == 0,
      length(aws_ssm_parameter.directory) == 0,
      length(xshield_enforcement_receipt.this) == 0,
    ])
    error_message = "with nothing published the module must create nothing, not even a receipt"
  }
  assert {
    condition     = output.published == false && output.version == null && output.summary.security_groups == 0
    error_message = "the outputs say nothing is published"
  }
}

run "first_version_applies_and_is_confirmed" {
  command = apply

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v1"
      security_groups = {
        "i-1"           = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "rds/orders-db" = { name = "ct-policy-0000000000d1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
      }
      ingress_rules = {
        "i-1/in/tcp/443/10.0.0.0/8" = {
          security_group = "i-1", ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
        "rds/orders-db/in/tcp/5432/10.1.0.0/16" = {
          security_group = "rds/orders-db", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.0/16", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules          = {}
      interface_attachments = { "i-1/eni-1" = { security_group = "i-1", network_interface_id = "eni-1", slot_limit = 5 } }
      directory = {
        "rds/orders-db" = { parameter_name = "/colortokens/v1/rds/orders-db/security-groups", handle = "rds/orders-db", security_groups = ["rds/orders-db"], tags = { ManagedBy = "ColorTokens" }, slot_limit = 5 }
      }
      assets = {
        "a-web" = { security_group = "i-1", attached_by = "pipeline" }
        "a-db"  = { security_group = "rds/orders-db", attached_by = "owner" }
      }
      withdrawing = []
    }
  }

  assert {
    condition     = length(aws_security_group.this) == 2 && length(aws_network_interface_sg_attachment.this) == 1 && length(aws_ssm_parameter.directory) == 1
    error_message = "the first version creates its groups, attachment and directory entry"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].snapshot_version == "v1" && toset(keys(xshield_enforcement_receipt.this[0].security_groups)) == toset(["i-1", "rds/orders-db"])
    error_message = "the first apply is confirmed with a receipt for exactly what it created"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].attachments["i-1/eni-1"] == "eni-1_${aws_security_group.this["i-1"].id}"
    error_message = "the receipt records each attachment by the ID that imports it, network interface first"
  }
}

# A changed rule, a new workload, and a contained one, all in one version.
run "changes_touch_only_what_changed" {
  command = apply

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v2"
      security_groups = {
        "i-1"           = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "i-2"           = { name = "ct-policy-0000000000a2", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "rds/orders-db" = { name = "ct-policy-0000000000d1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
      }
      ingress_rules = {
        "i-1/in/tcp/443/10.0.0.0/16" = {
          security_group = "i-1", ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/16", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
        "i-2/in/tcp/22/10.9.0.0/24" = {
          security_group = "i-2", ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.9.0.0/24", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
        "rds/orders-db/in/tcp/5432/10.1.0.0/16" = {
          security_group = "rds/orders-db", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.0/16", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules          = {}
      interface_attachments = { "i-2/eni-2" = { security_group = "i-2", network_interface_id = "eni-2", slot_limit = 5 } }
      directory = {
        "rds/orders-db" = { parameter_name = "/colortokens/v1/rds/orders-db/security-groups", handle = "rds/orders-db", security_groups = ["rds/orders-db"], tags = { ManagedBy = "ColorTokens" }, slot_limit = 5 }
      }
      assets = {
        "a-web" = { security_group = "i-1", attached_by = "pipeline" }
        "a-api" = { security_group = "i-2", attached_by = "pipeline" }
        "a-db"  = { security_group = "rds/orders-db", attached_by = "owner" }
      }
      withdrawing = []
    }
  }

  assert {
    condition     = output.security_group_ids["a-web"] == run.first_version_applies_and_is_confirmed.security_group_ids["a-web"] && output.security_group_ids["a-db"] == run.first_version_applies_and_is_confirmed.security_group_ids["a-db"]
    error_message = "groups that are still wanted keep their IDs; a replaced group would detach from every workload carrying it"
  }
  assert {
    condition     = keys(aws_vpc_security_group_ingress_rule.this) == ["i-1/in/tcp/443/10.0.0.0/16", "i-2/in/tcp/22/10.9.0.0/24", "rds/orders-db/in/tcp/5432/10.1.0.0/16"]
    error_message = "a changed rule is replaced under its new key and the old one is gone"
  }
  assert {
    condition     = keys(aws_network_interface_sg_attachment.this) == ["i-2/eni-2"]
    error_message = "the contained instance's attachment is removed and the new instance's added"
  }
  assert {
    condition     = jsondecode(aws_ssm_parameter.directory["rds/orders-db"].insecure_value).security_group_ids == [output.security_group_ids["a-db"]]
    error_message = "the database's directory entry still names the same group"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].snapshot_version == "v2" && length(xshield_enforcement_receipt.this[0].rules) == 3
    error_message = "the receipt moves to the new version"
  }
}

# Policy no longer covers the database, but its own workspace still attaches the
# group: the directory stops naming it and the group stays until it is detached.
run "withdrawn_group_outlives_its_attachment" {
  command = apply

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v3"
      security_groups = {
        "i-1"           = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "i-2"           = { name = "ct-policy-0000000000a2", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "rds/orders-db" = { name = "ct-policy-0000000000d1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
      }
      ingress_rules = {
        "i-1/in/tcp/443/10.0.0.0/16" = {
          security_group = "i-1", ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/16", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
        "i-2/in/tcp/22/10.9.0.0/24" = {
          security_group = "i-2", ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.9.0.0/24", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
        "rds/orders-db/in/tcp/5432/10.1.0.0/16" = {
          security_group = "rds/orders-db", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.0/16", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules          = {}
      interface_attachments = { "i-2/eni-2" = { security_group = "i-2", network_interface_id = "eni-2", slot_limit = 5 } }
      directory = {
        "rds/orders-db" = { parameter_name = "/colortokens/v1/rds/orders-db/security-groups", handle = "rds/orders-db", security_groups = [], tags = { ManagedBy = "ColorTokens" }, slot_limit = 5 }
      }
      assets = {
        "a-web" = { security_group = "i-1", attached_by = "pipeline" }
        "a-api" = { security_group = "i-2", attached_by = "pipeline" }
      }
      withdrawing = ["rds/orders-db"]
    }
  }

  assert {
    condition     = aws_security_group.this["rds/orders-db"].id == run.first_version_applies_and_is_confirmed.security_group_ids["a-db"] && contains(keys(aws_vpc_security_group_ingress_rule.this), "rds/orders-db/in/tcp/5432/10.1.0.0/16")
    error_message = "a group being withdrawn keeps its rules, because AWS refuses to delete a group that is still attached"
  }
  assert {
    condition     = jsondecode(aws_ssm_parameter.directory["rds/orders-db"].insecure_value).security_group_ids == [] && output.summary.withdrawing == tolist(["rds/orders-db"])
    error_message = "the directory tells the database's workspace to detach the group"
  }
}

run "detached_group_is_removed_and_the_rest_stay" {
  command = apply

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v4"
      security_groups = {
        "i-1" = { name = "ct-policy-0000000000a1", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
        "i-2" = { name = "ct-policy-0000000000a2", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-1", tags = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" } }
      }
      ingress_rules = {
        "i-1/in/tcp/443/10.0.0.0/16" = {
          security_group = "i-1", ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/16", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
        "i-2/in/tcp/22/10.9.0.0/24" = {
          security_group = "i-2", ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.9.0.0/24", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce", tags = { ManagedBy = "ColorTokens" }
        }
      }
      egress_rules          = {}
      interface_attachments = { "i-2/eni-2" = { security_group = "i-2", network_interface_id = "eni-2", slot_limit = 5 } }
      directory             = {}
      assets = {
        "a-web" = { security_group = "i-1", attached_by = "pipeline" }
        "a-api" = { security_group = "i-2", attached_by = "pipeline" }
      }
      withdrawing = []
    }
  }

  assert {
    condition     = keys(aws_security_group.this) == ["i-1", "i-2"] && length(aws_ssm_parameter.directory) == 0
    error_message = "the withdrawn group and its directory entry are removed once detached"
  }
  assert {
    condition     = output.security_group_ids["a-api"] == run.changes_touch_only_what_changed.security_group_ids["a-api"]
    error_message = "the groups still wanted are not replaced"
  }
}

# Xshield never unpublishes an account, so groups it rendered with nothing
# published mean the provider reads another tenant: refuse rather than remove.
run "refuses_to_remove_groups_when_nothing_is_published" {
  command = plan

  override_data {
    target = data.aws_security_groups.rendered[0]
    values = { ids = ["sg-0aaa", "sg-0bbb"] }
  }

  expect_failures = [data.aws_security_groups.rendered[0]]
}

run "off_removes_everything_and_still_confirms" {
  command = apply

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published             = true
      version               = "v5"
      security_groups       = {}
      ingress_rules         = {}
      egress_rules          = {}
      interface_attachments = {}
      directory             = {}
      assets                = {}
      withdrawing           = []
    }
  }

  assert {
    condition     = length(aws_security_group.this) + length(aws_vpc_security_group_ingress_rule.this) + length(aws_network_interface_sg_attachment.this) == 0
    error_message = "an empty published version removes every group"
  }
  assert {
    condition     = xshield_enforcement_receipt.this[0].snapshot_version == "v5"
    error_message = "and still confirms the version, so Xshield knows the removal was applied"
  }
}

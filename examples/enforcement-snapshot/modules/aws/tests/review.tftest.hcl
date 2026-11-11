# terraform test, offline: both providers are mocked. The snapshot below holds one instance, one database its
# own workspace attaches, and one Full control cohort group, with a rule for each way the review output words
# ports. Later runs override the snapshot with the version Xshield would serve at that point.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }
  mock_data "aws_security_groups" {
    defaults = { ids = [] }
  }
  mock_data "aws_network_interfaces" {
    defaults = { ids = ["eni-0web1a", "eni-0web1b", "eni-0legacy"] }
  }
  mock_data "aws_network_interface" {
    defaults = { security_groups = ["sg-0customer"], attachment = [] }
  }
}

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v42"
      security_groups = {
        "i-0web1" = {
          name        = "ct-policy-000000000001"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0example"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
        "rds/orders-db" = {
          name        = "ct-policy-000000000002"
          description = "ColorTokens add-only enforcement group"
          vpc_id      = "vpc-0example"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "policy", "ct:delivery" = "pipeline" }
        }
        "ct-cohort-0example" = {
          name        = "ct-cohort-0example"
          description = "ColorTokens split cohort group"
          vpc_id      = "vpc-0example"
          tags        = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1", "ct:split-group" = "sg-0example", "ct:delivery" = "pipeline" }
        }
      }
      ingress_rules = {
        "i-0web1/in/tcp/443/0.0.0.0/0" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "0.0.0.0/0", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/443/::/0" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = "::/0", prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/22/10.9.0.0/24" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 22, to_port = 22
          cidr_ipv4      = "10.9.0.0/24", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Admin access]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/22/10.6.0.0/16" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 22, to_port = 22
          cidr_ipv4      = "10.6.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Operations]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/80/10.6.0.0/16" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 80, to_port = 80
          cidr_ipv4      = "10.6.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Operations]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/443/10.6.0.0/16" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "10.6.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Operations]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/8000-8100/10.8.0.0/16" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 8000, to_port = 8100
          cidr_ipv4      = "10.8.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [App ports]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/0-65535/10.7.0.0/16" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 0, to_port = 65535
          cidr_ipv4      = "10.7.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Internal]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/-1/any/10.0.0.0/8" = {
          security_group = "i-0web1", ip_protocol = "-1", from_port = null, to_port = null
          cidr_ipv4      = "10.0.0.0/8", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [All traffic]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/udp/53/10.0.0.2/32" = {
          security_group = "i-0web1", ip_protocol = "udp", from_port = 53, to_port = 53
          cidr_ipv4      = "10.0.0.2/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Name and time]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/udp/123/10.0.0.2/32" = {
          security_group = "i-0web1", ip_protocol = "udp", from_port = 123, to_port = 123
          cidr_ipv4      = "10.0.0.2/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Name and time]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/icmp/8/10.0.0.0/8" = {
          security_group = "i-0web1", ip_protocol = "icmp", from_port = 8, to_port = -1
          cidr_ipv4      = "10.0.0.0/8", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/3306/10.30.0.0/16" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 3306, to_port = 3306
          cidr_ipv4      = "10.30.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens kept [web]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "kept", "ct:change-set" = "cs-2", "ct:split-group" = "sg-0example" }
        }
        "rds/orders-db/in/tcp/5432/sg-0app" = {
          security_group = "rds/orders-db", ip_protocol = "tcp", from_port = 5432, to_port = 5432
          cidr_ipv4      = null, cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = "sg-0app"
          description    = "ColorTokens authored enforce [Databases]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "ct-cohort-0example/in/tcp/0-79/10.20.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 0, to_port = 79
          cidr_ipv4      = "10.20.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/tcp/81-65535/10.20.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 81, to_port = 65535
          cidr_ipv4      = "10.20.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/udp/0-999/10.20.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "udp", from_port = 0, to_port = 999
          cidr_ipv4      = "10.20.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/udp/2000-65535/10.20.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "udp", from_port = 2000, to_port = 65535
          cidr_ipv4      = "10.20.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/tcp/0-21/10.21.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 0, to_port = 21
          cidr_ipv4      = "10.21.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/tcp/23-79/10.21.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 23, to_port = 79
          cidr_ipv4      = "10.21.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/tcp/81-65535/10.21.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 81, to_port = 65535
          cidr_ipv4      = "10.21.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/tcp/0-79/10.22.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 0, to_port = 79
          cidr_ipv4      = "10.22.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
        "ct-cohort-0example/in/tcp/80-65535/10.22.0.0/16" = {
          security_group = "ct-cohort-0example", ip_protocol = "tcp", from_port = 80, to_port = 65535
          cidr_ipv4      = "10.22.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = null, tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1" }
        }
      }
      egress_rules = {
        "i-0web1/out/tcp/443/pl-0example" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = null, cidr_ipv6 = null, prefix_list_id = "pl-0example", referenced_security_group_id = null
          description    = "ColorTokens authored enforce [SaaS endpoints]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
      }
      interface_attachments = {
        "i-0web1/eni-0web1a"             = { security_group = "i-0web1", network_interface_id = "eni-0web1a", slot_limit = 5 }
        "i-0web1/eni-0web1b"             = { security_group = "i-0web1", network_interface_id = "eni-0web1b", slot_limit = 5 }
        "ct-cohort-0example/eni-0web1a"  = { security_group = "ct-cohort-0example", network_interface_id = "eni-0web1a", slot_limit = null }
        "ct-cohort-0example/eni-0legacy" = { security_group = "ct-cohort-0example", network_interface_id = "eni-0legacy", slot_limit = null }
      }
      directory = {
        "rds/orders-db" = {
          parameter_name  = "/colortokens/v1/rds/orders-db/security-groups"
          handle          = "rds/orders-db"
          security_groups = ["rds/orders-db", "ct-cohort-0example"]
          tags            = { ManagedBy = "ColorTokens", "ct:delivery" = "pipeline" }
          slot_limit      = 5
        }
      }
      assets = {
        "asset-web-1"    = { security_group = "i-0web1", attached_by = "pipeline" }
        "asset-orders-1" = { security_group = "rds/orders-db", attached_by = "owner" }
      }
      withdrawing = []
    }
  }
  mock_data "xshield_enforcement_status" {
    defaults = { applied_attachments = {}, handover_attachments = {} }
  }
}

run "ports_are_said_in_words" {
  command = apply

  assert {
    condition     = contains(output.review, "Group for i-0web1 allows TCP 22 from 10.9.0.0/24 (template Admin access).")
    error_message = "a single port reads as the protocol and the port"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows TCP 8000-8100 from 10.8.0.0/16 (template App ports).")
    error_message = "a port range reads as the protocol and the range"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows all TCP from 10.7.0.0/16 (template Internal).")
    error_message = "every port of a protocol reads as all of that protocol"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows all traffic from 10.0.0.0/8 (template All traffic).")
    error_message = "every protocol reads as all traffic"
  }
  assert {
    condition     = contains(output.review, "Cohort group ct-cohort-0example allows all TCP except 80 from 10.20.0.0/16.")
    error_message = "two ranges that leave out one port read as all of the protocol except that port"
  }
  assert {
    condition     = contains(output.review, "Cohort group ct-cohort-0example allows all UDP except 1000-1999 from 10.20.0.0/16.")
    error_message = "two ranges that leave out one range read as all of the protocol except that range"
  }
  assert {
    condition     = contains(output.review, "Cohort group ct-cohort-0example allows all TCP except 22 and 80 from 10.21.0.0/16.")
    error_message = "three ranges that leave out two ports read as all of the protocol except those ports"
  }
  assert {
    condition     = contains(output.review, "Cohort group ct-cohort-0example allows TCP 0-79 and 80-65535 from 10.22.0.0/16.")
    error_message = "two ranges that leave no port out between them read as the ranges they are"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows UDP 53 and 123 from 10.0.0.2/32 (template Name and time).")
    error_message = "the ports one peer reaches under one template read as one sentence"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows TCP 22, 80 and 443 from 10.6.0.0/16 (template Operations).")
    error_message = "three ports one peer reaches read as a list"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows ICMP type 8 from 10.0.0.0/8.")
    error_message = "an ICMP rule reads as its type, and a rule without a description carries no name"
  }
}

run "each_group_says_whose_it_is" {
  command = apply

  assert {
    condition     = contains(output.review, "Group for i-0web1 is attached by this workspace to 2 network interfaces.")
    error_message = "an instance's group is named by its instance ID and says this workspace attaches it"
  }
  assert {
    condition     = contains(output.review, "Group for rds/orders-db is attached by the workspace that owns rds/orders-db.")
    error_message = "a database's group is named by its handle and says its own workspace attaches it"
  }
  assert {
    condition     = contains(output.review, "Cohort group ct-cohort-0example is for i-0web1, network interface eni-0legacy and rds/orders-db. It keeps access that customer group sg-0example gives up under change set cs-1.")
    error_message = "a cohort group names its workloads, its customer group and its change set"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows TCP 443 from 0.0.0.0/0 and ::/0 (template Web servers).")
    error_message = "the peers one rule set reaches read as one sentence"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows TCP 3306 from 10.30.0.0/16, kept from customer group web (sg-0example) under change set cs-2.")
    error_message = "a kept rule names its customer group and its change set"
  }
  assert {
    condition     = contains(output.review, "Group for i-0web1 allows TCP 443 to prefix list pl-0example (template SaaS endpoints).")
    error_message = "an egress rule reads as traffic to its peer"
  }
  assert {
    condition     = contains(output.review, "Group for rds/orders-db allows TCP 5432 from security group sg-0app (template Databases).")
    error_message = "a rule naming a security group says so"
  }
}

run "sentences_come_in_a_fixed_order_and_end_with_a_count" {
  command = apply

  assert {
    condition = output.review == tolist([
      "Cohort group ct-cohort-0example is for i-0web1, network interface eni-0legacy and rds/orders-db. It keeps access that customer group sg-0example gives up under change set cs-1.",
      "Cohort group ct-cohort-0example allows TCP 0-79 and 80-65535 from 10.22.0.0/16.",
      "Cohort group ct-cohort-0example allows all TCP except 22 and 80 from 10.21.0.0/16.",
      "Cohort group ct-cohort-0example allows all TCP except 80 from 10.20.0.0/16.",
      "Cohort group ct-cohort-0example allows all UDP except 1000-1999 from 10.20.0.0/16.",
      "Group for i-0web1 is attached by this workspace to 2 network interfaces.",
      "Group for i-0web1 allows all traffic from 10.0.0.0/8 (template All traffic).",
      "Group for i-0web1 allows ICMP type 8 from 10.0.0.0/8.",
      "Group for i-0web1 allows all TCP from 10.7.0.0/16 (template Internal).",
      "Group for i-0web1 allows TCP 22 from 10.9.0.0/24 (template Admin access).",
      "Group for i-0web1 allows TCP 22, 80 and 443 from 10.6.0.0/16 (template Operations).",
      "Group for i-0web1 allows TCP 443 from 0.0.0.0/0 and ::/0 (template Web servers).",
      "Group for i-0web1 allows TCP 3306 from 10.30.0.0/16, kept from customer group web (sg-0example) under change set cs-2.",
      "Group for i-0web1 allows TCP 8000-8100 from 10.8.0.0/16 (template App ports).",
      "Group for i-0web1 allows UDP 53 and 123 from 10.0.0.2/32 (template Name and time).",
      "Group for i-0web1 allows TCP 443 to prefix list pl-0example (template SaaS endpoints).",
      "Group for rds/orders-db is attached by the workspace that owns rds/orders-db.",
      "Group for rds/orders-db allows TCP 5432 from security group sg-0app (template Databases).",
      "Version v42 holds 3 groups, 24 rules and 4 interface attachments for 111111111111/us-east-1.",
    ])
    error_message = "cohort groups come first, then the rest by key; a group's sentences run inbound first, by protocol and lowest port; the last sentence counts what the version holds"
  }
}

# The same version planned again must give the same sentences, or every plan would show a change to the output.
run "an_unchanged_version_gives_the_same_sentences" {
  command = plan

  assert {
    condition     = output.review == run.sentences_come_in_a_fixed_order_and_end_with_a_count.review
    error_message = "a version that has not changed must not change the review output"
  }
  assert {
    condition = alltrue([
      length(aws_security_group.this) == 3,
      length(aws_vpc_security_group_ingress_rule.this) == 23,
      length(aws_vpc_security_group_egress_rule.this) == 1,
      length(aws_network_interface_sg_attachment.this) == 4,
      length(aws_ssm_parameter.directory) == 1,
    ])
    error_message = "the review output only reads the snapshot: the module still plans one resource per snapshot entry"
  }
}

# One rule's source narrows from 0.0.0.0/0 and ::/0 to 10.0.0.0/8. Only that rule's sentence and the count change.
run "a_changed_rule_changes_only_its_own_sentence" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      security_groups = {
        "i-0web1" = { name = "ct-policy-000000000001", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-0example", tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy" } }
      }
      ingress_rules = {
        "i-0web1/in/tcp/443/10.0.0.0/8" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 443, to_port = 443
          cidr_ipv4      = "10.0.0.0/8", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Web servers]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
        "i-0web1/in/tcp/22/10.9.0.0/24" = {
          security_group = "i-0web1", ip_protocol = "tcp", from_port = 22, to_port = 22
          cidr_ipv4      = "10.9.0.0/24", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null
          description    = "ColorTokens authored enforce [Admin access]", tags = { ManagedBy = "ColorTokens", "ct:origin" = "authored" }
        }
      }
      egress_rules = {}
      interface_attachments = {
        "i-0web1/eni-0web1a" = { security_group = "i-0web1", network_interface_id = "eni-0web1a", slot_limit = 5 }
      }
      directory   = {}
      assets      = { "asset-web-1" = { security_group = "i-0web1", attached_by = "pipeline" } }
      withdrawing = []
    }
  }

  assert {
    condition = output.review == tolist([
      "Group for i-0web1 is attached by this workspace to 1 network interface.",
      "Group for i-0web1 allows TCP 22 from 10.9.0.0/24 (template Admin access).",
      "Group for i-0web1 allows TCP 443 from 10.0.0.0/8 (template Web servers).",
      "Version v43 holds 1 group, 2 rules and 1 interface attachment for 111111111111/us-east-1.",
    ])
    error_message = "the changed rule reads with its new source, and counts of one are singular"
  }
  assert {
    condition     = contains(run.sentences_come_in_a_fixed_order_and_end_with_a_count.review, "Group for i-0web1 allows TCP 22 from 10.9.0.0/24 (template Admin access).")
    error_message = "the rule that did not change keeps its sentence word for word, so a plan hides it"
  }
}

run "nothing_published_is_one_sentence" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
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

  expect_failures = [check.xshield_published]

  assert {
    condition     = output.review == tolist(["Xshield has published nothing for 111111111111/us-east-1."])
    error_message = "with nothing published the review is one sentence that says so"
  }
}

run "an_empty_version_is_one_count" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published             = true
      version               = "v44"
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
    condition     = output.review == tolist(["Version v44 holds 0 groups, 0 rules and 0 interface attachments for 111111111111/us-east-1."])
    error_message = "a published version that holds nothing is one sentence that counts nothing"
  }
}

# A large account: more groups than review_max_groups, and a rule with more sources than one sentence names.
run "a_large_account_is_cut_short_and_says_so" {
  command = plan

  variables {
    review_max_groups = 2
  }

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "0123456789abcdef0123456789abcdef"
      security_groups = {
        "i-0web1"            = { name = "ct-policy-000000000001", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-0example", tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy" } }
        "i-0web2"            = { name = "ct-policy-000000000003", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-0example", tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy" } }
        "i-0web3"            = { name = "ct-policy-000000000004", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-0example", tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy" } }
        "ct-cohort-0example" = { name = "ct-cohort-0example", description = "ColorTokens split cohort group", vpc_id = "vpc-0example", tags = { ManagedBy = "ColorTokens", "ct:kind" = "cohort", "ct:change-set" = "cs-1", "ct:split-group" = "sg-0example" } }
      }
      ingress_rules = {
        "i-0web1/in/tcp/5432/10.1.0.1/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.1/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web1/in/tcp/5432/10.1.0.2/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.2/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web1/in/tcp/5432/10.1.0.3/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.3/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web1/in/tcp/5432/10.1.0.4/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.4/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web1/in/tcp/5432/10.1.0.5/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.5/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web1/in/tcp/5432/10.1.0.6/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.6/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web1/in/tcp/5432/10.1.0.7/32" = { security_group = "i-0web1", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.7/32", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
        "i-0web2/in/tcp/22/10.9.0.0/24"   = { security_group = "i-0web2", ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.9.0.0/24", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = null, tags = {} }
      }
      egress_rules          = {}
      interface_attachments = {}
      directory             = {}
      assets                = {}
      withdrawing           = []
    }
  }

  assert {
    condition = output.review == tolist([
      "Cohort group ct-cohort-0example is on no workload in this version. It keeps access that customer group sg-0example gives up under change set cs-1.",
      "Group for i-0web1 is attached to nothing in this version.",
      "Group for i-0web1 allows TCP 5432 from 10.1.0.1/32, 10.1.0.2/32, 10.1.0.3/32, 10.1.0.4/32, 10.1.0.5/32 and 2 more.",
      "2 more groups are not described here. Raise review_max_groups to describe them.",
      "Version 0123456789ab holds 4 groups, 8 rules and 0 interface attachments for 111111111111/us-east-1.",
    ])
    error_message = "cohort groups are described first, a sentence names five peers and counts the rest, the groups past the limit are counted, and the version is cut to twelve characters"
  }
}

# Policy no longer covers the database, but its own workspace still attaches the group.
run "a_withdrawn_group_says_so" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_snapshot.this
    values = {
      published = true
      version   = "v45"
      security_groups = {
        "rds/orders-db" = { name = "ct-policy-000000000002", description = "ColorTokens add-only enforcement group", vpc_id = "vpc-0example", tags = { ManagedBy = "ColorTokens", "ct:kind" = "policy" } }
      }
      ingress_rules = {
        "rds/orders-db/in/tcp/5432/10.1.0.0/16" = { security_group = "rds/orders-db", ip_protocol = "tcp", from_port = 5432, to_port = 5432, cidr_ipv4 = "10.1.0.0/16", cidr_ipv6 = null, prefix_list_id = null, referenced_security_group_id = null, description = "ColorTokens authored enforce [Databases]", tags = {} }
      }
      egress_rules          = {}
      interface_attachments = {}
      directory = {
        "rds/orders-db" = { parameter_name = "/colortokens/v1/rds/orders-db/security-groups", handle = "rds/orders-db", security_groups = [], tags = { ManagedBy = "ColorTokens" }, slot_limit = 5 }
      }
      assets      = {}
      withdrawing = ["rds/orders-db"]
    }
  }

  assert {
    condition = output.review == tolist([
      "Group for rds/orders-db is being withdrawn. Policy no longer uses it, and it keeps its rules until Xshield sees it detached.",
      "Group for rds/orders-db allows TCP 5432 from 10.1.0.0/16 (template Databases).",
      "Version v45 holds 1 group, 1 rule and 0 interface attachments for 111111111111/us-east-1.",
    ])
    error_message = "a group being withdrawn says so, and still lists the rules it keeps"
  }
}

run "a_limit_below_zero_is_refused" {
  command = plan

  variables {
    review_max_groups = -1
  }

  expect_failures = [var.review_max_groups]
}

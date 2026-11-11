# terraform test, offline: both providers are mocked. The caller declares rules for the group web with every
# shape of ports and peer the review output words. Each run overrides what Xshield says about those rules.

mock_provider "aws" {}

mock_provider "xshield" {
  mock_data "xshield_aws_security_group_rules" {
    defaults = {
      published = true
      version   = "v7"
      ingress_rules = {
        https_office = {
          ip_protocol    = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      egress_rules        = {}
      revoked             = []
      pending             = []
      reopens             = []
      undeclared_pending  = []
      undeclared_restores = []
    }
  }
}

variables {
  xshield_changes   = { cloud_account_id = "111111111111", region = "us-east-1", groups = { web = ["vpc-0example"] } }
  vpc_id            = "vpc-0example"
  group_name        = "web"
  security_group_id = "sg-0example"

  ingress = {
    https_office  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8" }
    ssh_all       = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "0.0.0.0/0" }
    ssh_numbered  = { ip_protocol = "6", from_port = 22, to_port = 22, cidr_ipv4 = "10.9.0.0/24" }
    app_range     = { ip_protocol = "tcp", from_port = 8000, to_port = 8100, cidr_ipv4 = "10.8.0.0/16" }
    tcp_internal  = { ip_protocol = "tcp", from_port = 0, to_port = 65535, cidr_ipv4 = "10.0.0.0/8" }
    everything_v6 = { ip_protocol = "-1", cidr_ipv6 = "::/0" }
    dns_from_lb   = { ip_protocol = "udp", from_port = 53, to_port = 53, referenced_security_group_id = "sg-0lb" }
    ping          = { ip_protocol = "icmp", from_port = 8, to_port = -1, cidr_ipv4 = "10.0.0.0/8" }
  }
  egress = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
    s3  = { ip_protocol = "tcp", from_port = 443, to_port = 443, prefix_list_id = "pl-0example" }
    esp = { ip_protocol = "50", cidr_ipv4 = "10.0.0.0/8" }
  }
}

run "a_group_no_change_applies_to_has_an_empty_review" {
  command = plan

  variables {
    xshield_changes = { cloud_account_id = "111111111111", region = "us-east-1", groups = { db = ["vpc-0example"] } }
  }

  assert {
    condition     = length(output.review) == 0
    error_message = "a group no change applies to must have nothing to review"
  }
  assert {
    condition     = length(data.xshield_aws_security_group_rules.this) == 0
    error_message = "the review must not make an unchanged group read its rules from Xshield"
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 8 && length(aws_vpc_security_group_egress_rule.this) == 3
    error_message = "an unchanged group still declares every rule the caller passes"
  }
}

run "a_change_that_leaves_every_rule_in_has_an_empty_review" {
  command = plan

  assert {
    condition     = output.changed && length(output.review) == 0
    error_message = "a change that takes nothing out and waits on nothing must have nothing to review"
  }
}

run "rules_taken_out_and_waiting_are_said_in_words" {
  command = plan

  override_data {
    target = data.xshield_aws_security_group_rules.this[0]
    values = {
      published = true
      version   = "v8"
      ingress_rules = {
        https_office = {
          ip_protocol    = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      egress_rules        = {}
      revoked             = ["ingress/everything_v6", "ingress/ssh_all", "ingress/tcp_internal", "egress/all"]
      pending             = ["ingress/app_range", "ingress/dns_from_lb", "ingress/ping", "ingress/ssh_numbered", "egress/esp", "egress/s3"]
      reopens             = []
      undeclared_pending  = []
      undeclared_restores = []
    }
  }

  assert {
    condition     = contains(output.review, "Group web: rule ingress/ssh_all (TCP 22 from 0.0.0.0/0) is taken out by Xshield.")
    error_message = "a rule Xshield has left out reads as taken out, with its key and a single port as the protocol and the port"
  }
  assert {
    condition     = contains(output.review, "Group web: rule ingress/app_range (TCP 8000-8100 from 10.8.0.0/16) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.")
    error_message = "a rule Xshield is waiting to leave out reads as waiting, with a port range as the protocol and the range"
  }
  assert {
    condition     = contains(output.review, "Group web: rule ingress/tcp_internal (all TCP from 10.0.0.0/8) is taken out by Xshield.")
    error_message = "every port of a protocol reads as all of that protocol"
  }
  assert {
    condition     = contains(output.review, "Group web: rule ingress/everything_v6 (all traffic from ::/0) is taken out by Xshield.")
    error_message = "every protocol reads as all traffic, from an IPv6 source too"
  }
  assert {
    condition     = contains(output.review, "Group web: rule egress/all (all traffic to 0.0.0.0/0) is taken out by Xshield.")
    error_message = "an egress rule reads as traffic to its peer"
  }
  assert {
    condition     = contains(output.review, "Group web: rule ingress/dns_from_lb (UDP 53 from security group sg-0lb) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.")
    error_message = "a rule naming a security group says so"
  }
  assert {
    condition     = contains(output.review, "Group web: rule egress/s3 (TCP 443 to prefix list pl-0example) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.")
    error_message = "a rule naming a prefix list says so"
  }
  assert {
    condition     = contains(output.review, "Group web: rule ingress/ping (ICMP type 8 from 10.0.0.0/8) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.")
    error_message = "an ICMP rule reads as its type"
  }
  assert {
    condition     = contains(output.review, "Group web: rule ingress/ssh_numbered (TCP 22 from 10.9.0.0/24) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.")
    error_message = "a protocol given by its number reads by its name"
  }
  assert {
    condition     = contains(output.review, "Group web: rule egress/esp (protocol 50 to 10.0.0.0/8) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.")
    error_message = "a protocol without a name reads by its number"
  }
  assert {
    condition     = length(output.review) == 10 && length([for line in slice(output.review, 0, 4) : line if endswith(line, "is taken out by Xshield.")]) == 4
    error_message = "there is one sentence for each rule, the rules taken out first"
  }
  assert {
    condition     = toset(keys(aws_vpc_security_group_ingress_rule.this)) == toset(["https_office"]) && length(aws_vpc_security_group_egress_rule.this) == 0
    error_message = "the review only reads what Xshield says: the group still declares exactly the rules Xshield returns"
  }
}

run "the_same_answer_gives_the_same_sentences" {
  command = plan

  override_data {
    target = data.xshield_aws_security_group_rules.this[0]
    values = {
      published = true
      version   = "v8"
      ingress_rules = {
        https_office = {
          ip_protocol    = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      egress_rules        = {}
      revoked             = ["ingress/everything_v6", "ingress/ssh_all", "ingress/tcp_internal", "egress/all"]
      pending             = ["ingress/app_range", "ingress/dns_from_lb", "ingress/ping", "ingress/ssh_numbered", "egress/esp", "egress/s3"]
      reopens             = []
      undeclared_pending  = []
      undeclared_restores = []
    }
  }

  assert {
    condition     = output.review == run.rules_taken_out_and_waiting_are_said_in_words.review
    error_message = "the same answer from Xshield must not change the review output"
  }
}

# A rule that undoes part of a change, and rules a change needs that the group no longer declares, each name
# their change set.
run "rules_a_change_set_needs_say_which_change_set" {
  command = plan

  override_data {
    target = data.xshield_aws_security_group_rules.this[0]
    values = {
      published = true
      version   = "v9"
      ingress_rules = {
        https_office = {
          ip_protocol    = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8", cidr_ipv6 = null
          prefix_list_id = null, referenced_security_group_id = null, description = null, tags = null
        }
      }
      egress_rules = {}
      revoked      = []
      pending      = []
      reopens      = [{ rule = "ingress/tcp_internal", change_set = "cs-1" }]
      undeclared_pending = [{
        direction      = "ingress", ip_protocol = "tcp", from_port = 3389, to_port = 3389, cidr_ipv4 = "0.0.0.0/0", cidr_ipv6 = null
        prefix_list_id = null, referenced_security_group_id = null, change_set = "cs-2"
      }]
      undeclared_restores = [{
        direction      = "egress", ip_protocol = "-1", from_port = null, to_port = null, cidr_ipv4 = "0.0.0.0/0", cidr_ipv6 = null
        prefix_list_id = null, referenced_security_group_id = null, change_set = "cs-3"
      }]
    }
  }

  assert {
    condition = output.review == tolist([
      "Group web: rule ingress/tcp_internal (all TCP from 10.0.0.0/8) gives workloads in the group traffic that change set cs-1 takes from them.",
      "Group web: TCP 3389 from 0.0.0.0/0 is no longer declared, and change set cs-2 is waiting to take it out. Declare it again, or the workloads that keep it lose it early. Xshield leaves it out once it is safe.",
      "Group web: all traffic to 0.0.0.0/0 is no longer declared, and the revert of change set cs-3 puts it back. Declare it again: the revert waits until the group holds it.",
    ])
    error_message = "a rule that gives traffic back, a rule waiting that the group dropped, and a rule a revert puts back each say their change set"
  }
}

# Xshield only names keys the group declares. If it ever named another, the plan must still go through.
run "a_key_the_group_does_not_declare_is_named_without_words" {
  command = plan

  override_data {
    target = data.xshield_aws_security_group_rules.this[0]
    values = {
      published           = true
      version             = "v10"
      ingress_rules       = {}
      egress_rules        = {}
      revoked             = ["ingress/not_declared"]
      pending             = []
      reopens             = []
      undeclared_pending  = []
      undeclared_restores = []
    }
  }

  assert {
    condition     = output.review == tolist(["Group web: rule ingress/not_declared is taken out by Xshield."])
    error_message = "a key with no declared rule reads by its key alone"
  }
}

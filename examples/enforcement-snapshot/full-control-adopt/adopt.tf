# One-time. Carries the rules that are already in AWS into the rules modules, so
# the first plan creates and destroys nothing there. Add it in the same change
# as main.tf, apply, then delete it.
#
# Each import names a rule by its security group rule ID. To list a group's
# rules with their IDs:
#
#   aws ec2 describe-security-group-rules --filters Name=group-id,Values=<group ID>

# web: the rules were inline blocks, which Terraform tracked only as part of the
# group. Each one is imported under its key.
import {
  to = module.web_rules.aws_vpc_security_group_ingress_rule.this["https_all"]
  id = "sgr-0a1b2c3d4e5f60101"
}

import {
  to = module.web_rules.aws_vpc_security_group_ingress_rule.this["ssh_office"]
  id = "sgr-0a1b2c3d4e5f60102"
}

import {
  to = module.web_rules.aws_vpc_security_group_egress_rule.this["all"]
  id = "sgr-0a1b2c3d4e5f60103"
}

# app: the rules were aws_security_group_rule resources. Terraform cannot move
# that type into the one the module uses, so each old resource is forgotten,
# which leaves its rule in AWS, and the rule is imported under its key. Deleting
# the old resource blocks without these removed blocks would destroy the rules.
removed {
  from = aws_security_group_rule.app_from_web

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_security_group_rule.app_ssh_office

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_security_group_rule.app_to_s3

  lifecycle {
    destroy = false
  }
}

import {
  to = module.app_rules.aws_vpc_security_group_ingress_rule.this["from_web"]
  id = "sgr-0a1b2c3d4e5f60201"
}

import {
  to = module.app_rules.aws_vpc_security_group_ingress_rule.this["ssh_office_a"]
  id = "sgr-0a1b2c3d4e5f60202"
}

import {
  to = module.app_rules.aws_vpc_security_group_ingress_rule.this["ssh_office_b"]
  id = "sgr-0a1b2c3d4e5f60203"
}

import {
  to = module.app_rules.aws_vpc_security_group_egress_rule.this["s3"]
  id = "sgr-0a1b2c3d4e5f60204"
}

# batch: no Terraform managed the group, so the group is imported as well.
import {
  to = aws_security_group.batch
  id = "sg-0a1b2c3d4e5f60300"
}

import {
  to = module.batch_rules.aws_vpc_security_group_ingress_rule.this["all_from_vpc"]
  id = "sgr-0a1b2c3d4e5f60301"
}

import {
  to = module.batch_rules.aws_vpc_security_group_egress_rule.this["all"]
  id = "sgr-0a1b2c3d4e5f60302"
}

# The web team's own workspace, in an account under Full control: its security
# group and the rules the team chooses for it. It stands in for a workspace you
# already have. Under Full control Xshield also narrows a broad rule of a group
# of your own, and in pipeline delivery that goes through the code of the
# workspace that owns the group. So the team changed two things, once, both
# marked below. What the team added is in xshield.tf.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    # Changed for Xshield: the workspace now reads Xshield.
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

resource "aws_security_group" "web" {
  name        = "web"
  description = "Rules the web team declares for its servers"
  vpc_id      = var.vpc_id
}

# Changed for Xshield: each rule was an aws_vpc_security_group_ingress_rule or
# aws_vpc_security_group_egress_rule resource, and is now a map entry with the
# same arguments, under a key the team chooses and keeps. The team still
# decides every rule. Xshield decides only whether a declared rule is created,
# and the team keeps a rule's entry after Xshield has taken the rule out.
module "web_rules" {
  source = "../modules/aws-security-group-rules"

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = var.vpc_id
  group_name        = aws_security_group.web.name
  security_group_id = aws_security_group.web.id

  ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
  egress_rules = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
  }
}

variable "vpc_id" {
  description = "VPC the group is in."
  type        = string
}

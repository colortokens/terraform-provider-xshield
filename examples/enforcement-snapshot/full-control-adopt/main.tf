# A workspace that existed before Xshield, in an account under Full control,
# after its one-time change. It stands in for three security groups you are
# likely to have, each of which declared its rules a different way before:
#
#   web    its rules were inline ingress and egress blocks of the group
#   app    its rules were aws_security_group_rule resources
#   batch  no Terraform managed it: someone made it in the console
#
# Each group's rules are now a map passed to the rules module, exactly as in
# ../full-control. The rules are already in AWS, so adopt.tf carries each one
# into the module: the first plan imports them, and adds and destroys nothing.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

# Before: this block held two ingress blocks and an egress block. They were all
# deleted in this one change. A group left with no ingress block keeps the
# ingress rules it has, and the same holds for egress, so the plan shows no
# change to the group. Deleting only some of a direction's blocks would revoke
# the rules of the blocks deleted.
resource "aws_security_group" "web" {
  name        = "web"
  description = "Web servers"
  vpc_id      = var.vpc_id
}

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

resource "aws_security_group" "app" {
  name        = "app"
  description = "Application servers"
  vpc_id      = var.vpc_id
}

# Before: three aws_security_group_rule resources. One of them listed both
# office ranges in cidr_blocks, which is two rules in AWS, so it is two entries
# here. A rule may name another group or a prefix list as it did before.
module "app_rules" {
  source = "../modules/aws-security-group-rules"

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = var.vpc_id
  group_name        = aws_security_group.app.name
  security_group_id = aws_security_group.app.id

  ingress_rules = {
    from_web     = { ip_protocol = "tcp", from_port = 8080, to_port = 8080, referenced_security_group_id = aws_security_group.web.id }
    ssh_office_a = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
    ssh_office_b = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "172.16.0.0/12" }
  }
  egress_rules = {
    s3 = { ip_protocol = "tcp", from_port = 443, to_port = 443, prefix_list_id = var.s3_prefix_list_id }
  }
}

# Before: nothing. The group was made by hand, so this block is new, and
# adopt.tf imports the group under it. Its name and description are the group's
# own, to the letter: either one differing makes the plan replace the group.
resource "aws_security_group" "batch" {
  name        = "batch"
  description = "launch-wizard-3 created 2019-04-02T09:15:41.120Z"
  vpc_id      = var.vpc_id
}

module "batch_rules" {
  source = "../modules/aws-security-group-rules"

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = var.vpc_id
  group_name        = aws_security_group.batch.name
  security_group_id = aws_security_group.batch.id

  ingress_rules = {
    all_from_vpc = { ip_protocol = "-1", cidr_ipv4 = "10.20.0.0/16" }
  }
  egress_rules = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
  }
}

variable "vpc_id" {
  description = "VPC the groups are in."
  type        = string
}

variable "s3_prefix_list_id" {
  description = "The region's Amazon S3 prefix list, which the app group's egress rule names."
  type        = string
}

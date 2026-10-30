# Route a group you own through Xshield's Full control: declare the rules that come back.
# Values known before the plan: an attribute of a resource in this configuration would defer the
# data source to the apply, and its rules could not drive for_each.
variable "vpc_id" {
  type = string
}

locals {
  web_ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
}

data "xshield_security_group_rules" "web" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
  vpc_id           = var.vpc_id
  group_name       = "web"

  ingress = local.web_ingress_rules
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each = data.xshield_security_group_rules.web.ingress_rules

  security_group_id            = aws_security_group.web.id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  referenced_security_group_id = each.value.referenced_security_group_id
  description                  = each.value.description
  tags                         = each.value.tags
}

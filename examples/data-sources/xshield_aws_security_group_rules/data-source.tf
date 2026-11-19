# Route a group you own through Xshield's Full control. The aws-security-group-rules module in
# examples/enforcement-snapshot/modules wires all of this for you; written by hand, keep every part below.
# Read the account's changes once; a group they do not list keeps the rules its code declares without reading
# them from Xshield, so its VPC and rules may be values the plan learns only at apply, as in a configuration
# that creates them.
data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id
}

locals {
  web_ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }

  web_vpcs_changed = lookup(data.xshield_aws_security_group_changes.this.groups, aws_security_group.web.name, [])
  web_changed      = length(local.web_vpcs_changed) > 0 ? contains(local.web_vpcs_changed, aws_vpc.main.id) : false
}

data "xshield_aws_security_group_rules" "web" {
  count = local.web_changed ? 1 : 0

  cloud_account_id = data.xshield_aws_security_group_changes.this.cloud_account_id
  region           = data.xshield_aws_security_group_changes.this.region
  vpc_id           = aws_vpc.main.id
  group_name       = aws_security_group.web.name

  declared_ingress_rules = local.web_ingress_rules
}

locals {
  web_revoked = local.web_changed ? data.xshield_aws_security_group_rules.web[0].revoked_rules : []
}

# While a change applies to the group, two receipts tell Xshield what this apply took from it. The rules wait
# for the applying receipt, which Xshield refuses for a plan made before a revert, so such a plan stops before
# any rule changes. With create_before_destroy, a rule taken out goes only after the applied receipt; without
# it, Terraform destroys the rule before the applying receipt is sent, and a refused plan still removes it.
resource "xshield_aws_security_group_changes_receipt" "web_applying" {
  count = local.web_changed ? 1 : 0

  stage            = "applying"
  cloud_account_id = data.xshield_aws_security_group_rules.web[0].cloud_account_id
  region           = data.xshield_aws_security_group_rules.web[0].region
  version          = data.xshield_aws_security_group_rules.web[0].version
  groups = {
    (data.xshield_aws_security_group_rules.web[0].security_group_id) = data.xshield_aws_security_group_rules.web[0].change_sets
  }
}

# Keeps your own rule blocks: only the rules Xshield has left out drop from for_each.
resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each = { for key, rule in local.web_ingress_rules : key => rule if !contains(local.web_revoked, "ingress/${key}") }

  security_group_id = aws_security_group.web.id
  ip_protocol       = each.value.ip_protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_ipv4         = each.value.cidr_ipv4

  depends_on = [xshield_aws_security_group_changes_receipt.web_applying]

  lifecycle {
    create_before_destroy = true
  }
}

resource "xshield_aws_security_group_changes_receipt" "web_applied" {
  count = local.web_changed ? 1 : 0

  stage            = "applied"
  receipt_id       = xshield_aws_security_group_changes_receipt.web_applying[0].id
  cloud_account_id = data.xshield_aws_security_group_rules.web[0].cloud_account_id
  region           = data.xshield_aws_security_group_rules.web[0].region
  version          = data.xshield_aws_security_group_rules.web[0].version
  groups = {
    (data.xshield_aws_security_group_rules.web[0].security_group_id) = data.xshield_aws_security_group_rules.web[0].change_sets
  }

  depends_on = [aws_vpc_security_group_ingress_rule.web]
}

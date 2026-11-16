# The aws-security-group-rules module sends these for you. Written by hand, both
# report what the same read of xshield_aws_security_group_rules gave. The rules
# depend on the applying receipt, so Xshield can refuse a plan made before a
# revert before any rule changes, and the applied receipt depends on the rules.
# Without create_before_destroy on the rules, Terraform destroys a rule taken out
# of the configuration before it sends the applying receipt.
resource "xshield_aws_security_group_changes_receipt" "applying" {
  stage            = "applying"
  cloud_account_id = data.xshield_aws_security_group_rules.web.cloud_account_id
  region           = data.xshield_aws_security_group_rules.web.region
  version          = data.xshield_aws_security_group_rules.web.version
  groups = {
    (data.xshield_aws_security_group_rules.web.security_group_id) = data.xshield_aws_security_group_rules.web.change_sets
  }
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each = data.xshield_aws_security_group_rules.web.ingress_rules

  security_group_id = aws_security_group.web.id
  ip_protocol       = each.value.ip_protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_ipv4         = each.value.cidr_ipv4

  depends_on = [xshield_aws_security_group_changes_receipt.applying]

  lifecycle {
    create_before_destroy = true
  }
}

resource "xshield_aws_security_group_changes_receipt" "applied" {
  stage            = "applied"
  receipt_id       = xshield_aws_security_group_changes_receipt.applying.id
  cloud_account_id = data.xshield_aws_security_group_rules.web.cloud_account_id
  region           = data.xshield_aws_security_group_rules.web.region
  version          = data.xshield_aws_security_group_rules.web.version
  groups = {
    (data.xshield_aws_security_group_rules.web.security_group_id) = data.xshield_aws_security_group_rules.web.change_sets
  }

  depends_on = [aws_vpc_security_group_ingress_rule.web]
}

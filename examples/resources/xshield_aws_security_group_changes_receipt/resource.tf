# The aws-security-group-rules module sends this for you. Written by hand, it
# reports what the same read of xshield_aws_security_group_rules gave, and
# depends on the rules it applied, so it is sent only once they are applied.
resource "xshield_aws_security_group_changes_receipt" "web" {
  cloud_account_id = data.xshield_aws_security_group_rules.web.cloud_account_id
  region           = data.xshield_aws_security_group_rules.web.region
  version          = data.xshield_aws_security_group_rules.web.version
  groups = {
    (data.xshield_aws_security_group_rules.web.security_group_id) = data.xshield_aws_security_group_rules.web.change_sets
  }

  depends_on = [aws_vpc_security_group_ingress_rule.web, aws_vpc_security_group_egress_rule.web]
}

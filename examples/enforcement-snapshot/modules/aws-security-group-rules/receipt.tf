# Tells Xshield, once the group's rules are applied, which change sets they were applied from and in what state. A
# revert of a change keeps the access it moved into ct-cohort- groups until this receipt reports the revert, so a
# plan saved before the revert and applied after it keeps the access instead of taking the rules out again.

resource "xshield_aws_security_group_changes_receipt" "this" {
  count = local.changed ? 1 : 0

  cloud_account_id = data.xshield_aws_security_group_rules.this[0].cloud_account_id
  region           = data.xshield_aws_security_group_rules.this[0].region
  version          = data.xshield_aws_security_group_rules.this[0].version
  groups = {
    (data.xshield_aws_security_group_rules.this[0].security_group_id) = data.xshield_aws_security_group_rules.this[0].change_sets
  }
  label = var.receipt_label

  depends_on = [aws_vpc_security_group_ingress_rule.this, aws_vpc_security_group_egress_rule.this]
}

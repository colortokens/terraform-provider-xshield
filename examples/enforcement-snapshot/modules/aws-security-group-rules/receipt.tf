# Tells Xshield which change sets the group's rules come from and in what state, twice in each apply and under one ID.
# The applying receipt goes first: rules are created or updated after it, and a rule taken out is destroyed only after
# the applied receipt, so Xshield refuses a plan made before a revert while no rule has changed. A revert keeps the access
# it moved into ct-cohort- groups until an applied receipt reports the revert.

resource "xshield_aws_security_group_changes_receipt" "applying" {
  count = local.changed ? 1 : 0

  stage            = "applying"
  cloud_account_id = data.xshield_aws_security_group_rules.this[0].cloud_account_id
  region           = data.xshield_aws_security_group_rules.this[0].region
  version          = data.xshield_aws_security_group_rules.this[0].version
  groups = {
    (data.xshield_aws_security_group_rules.this[0].security_group_id) = data.xshield_aws_security_group_rules.this[0].change_sets
  }
  label = var.receipt_label
}

resource "xshield_aws_security_group_changes_receipt" "applied" {
  count = local.changed ? 1 : 0

  stage            = "applied"
  receipt_id       = xshield_aws_security_group_changes_receipt.applying[0].id
  cloud_account_id = data.xshield_aws_security_group_rules.this[0].cloud_account_id
  region           = data.xshield_aws_security_group_rules.this[0].region
  version          = data.xshield_aws_security_group_rules.this[0].version
  groups = {
    (data.xshield_aws_security_group_rules.this[0].security_group_id) = data.xshield_aws_security_group_rules.this[0].change_sets
  }
  label = var.receipt_label

  depends_on = [aws_vpc_security_group_ingress_rule.this, aws_vpc_security_group_egress_rule.this]
}

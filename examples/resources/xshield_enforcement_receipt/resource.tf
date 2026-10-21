# Report the applied snapshot and the cloud resource created for each construct
# in it. Referencing the rendered resources means the receipt is only sent once
# they all exist.
resource "xshield_enforcement_receipt" "this" {
  cloud_account_id = data.xshield_enforcement_snapshot.this.cloud_account_id
  region           = data.xshield_enforcement_snapshot.this.region
  workspace        = "ct-enforcement-123456789012-us-east-1"
  snapshot_version = data.xshield_enforcement_snapshot.this.version
  content_hash     = data.xshield_enforcement_snapshot.this.content_hash
  vpc_id           = var.vpc_id

  groups       = { for slug, sg in aws_security_group.group : slug => sg.id }
  markers      = { for slug, sg in aws_security_group.marker : slug => sg.id }
  address_sets = { for slug, pl in aws_ec2_managed_prefix_list.pl : slug => pl.id }
  rules = merge(
    { for key, r in aws_vpc_security_group_ingress_rule.ingress : key => r.security_group_rule_id },
    { for key, r in aws_vpc_security_group_egress_rule.egress : key => r.security_group_rule_id },
  )
}

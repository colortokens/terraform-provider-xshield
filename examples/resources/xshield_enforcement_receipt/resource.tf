# The aws enforcement module sends this for you. Written by hand, it must list
# the ID of every resource the snapshot asks for, and reference them, so it is
# sent only once they all exist.
resource "xshield_enforcement_receipt" "this" {
  cloud_account_id = data.xshield_enforcement_snapshot.this.cloud_account_id
  region           = data.xshield_enforcement_snapshot.this.region
  workspace        = "xshield-enforcement-123456789012-us-east-1"
  snapshot_version = data.xshield_enforcement_snapshot.this.version

  security_groups = { for key, group in aws_security_group.this : key => group.id }
  rules = merge(
    { for key, rule in aws_vpc_security_group_ingress_rule.this : key => rule.security_group_rule_id },
    { for key, rule in aws_vpc_security_group_egress_rule.this : key => rule.security_group_rule_id },
  )
  attachments = { for key, attachment in aws_network_interface_sg_attachment.this : key => attachment.id }
}

# Hands an account to connector delivery without removing what the cloud connector now keeps: replace
# the module "xshield_enforcement" block with this one, remove the outputs that read the module (summary and
# xshield_review in enforcement/main.tf), and apply once. The groups, rules, attachments, network ACL
# entries and directory parameters stay in the account; Terraform only stops managing them. Delete this
# file afterwards, and remove the directory parameters once no workspace looks its groups up any more.
#
# The network ACL entries stay in place, and Xshield no longer tracks them; a cloud connector that blocks
# addresses on network ACLs itself may change or delete an entry at a rule number it uses. Before you apply,
# list them from the state, which also holds any an apply created whose receipt Xshield refused, and the old
# number of a deny that apply was moving, kept as a deposed object that terraform state show leaves out:
#   terraform show -json | jq -r '.values.root_module | .. | objects | select(.type? == "aws_network_acl_rule") | .values | "\(.network_acl_id) \(.rule_number) \(.egress) \(.cidr_block // .ipv6_cidr_block)"'
# Each line gives an entry's network_acl_id, rule_number, egress and address. Once an address is no
# longer to be blocked, as when it leaves the malicious IP block template or the template is unassigned, check
# that the entry at its number still denies that address on all protocols, as the number may hold another entry
# by then, and only then delete it:
#   aws ec2 describe-network-acls --network-acl-ids <network_acl_id> --query 'NetworkAcls[].Entries[?RuleNumber==`<rule_number>` && Egress==`<egress>`]'
#   aws ec2 delete-network-acl-entry --network-acl-id <network_acl_id> --rule-number <rule_number> --ingress
# with --egress instead of --ingress for an entry whose egress is true.
removed {
  from = module.xshield_enforcement

  lifecycle {
    destroy = false
  }
}

# Hands an account to connector delivery without removing what the cloud connector now keeps: replace
# the module "xshield_enforcement" block with this one, remove the outputs that read the module (summary and
# xshield_review in enforcement/main.tf), and apply once. The groups, rules, attachments, network ACL
# entries and directory parameters stay in the account; Terraform only stops managing them. Delete this
# file afterwards, and remove the directory parameters once no workspace looks its groups up any more.
#
# The cloud connector does not take the network ACL entries over: it deletes only entries it wrote itself,
# so each one keeps denying its address until you delete it. Before you apply, save them from the state:
#   terraform state show 'module.xshield_enforcement.xshield_enforcement_receipt.this[0]'
# Its network_acl_entries maps each <network ACL ID>/<in|out>/<address> to <network ACL ID>:<rule number>:-1:<egress>.
# Once an address is no longer to be blocked, as when it leaves the malicious IP block template or the template
# is unassigned, delete its entry with aws ec2 delete-network-acl-entry.
removed {
  from = module.xshield_enforcement

  lifecycle {
    destroy = false
  }
}

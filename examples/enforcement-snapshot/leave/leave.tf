# Hands an account to connector delivery without removing what the cloud connector now keeps: replace
# the module "xshield_enforcement" block with this one, remove the outputs that read the module (summary and
# xshield_review in enforcement/main.tf), and apply once. The groups, rules, attachments
# and directory parameters stay in the account; Terraform only stops managing them. Delete this file
# afterwards, and remove the directory parameters once no workspace looks its groups up any more.
removed {
  from = module.xshield_enforcement

  lifecycle {
    destroy = false
  }
}

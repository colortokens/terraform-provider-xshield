output "version" {
  description = "Snapshot version this configuration applies. Null while Xshield has published nothing for the account and region."
  value       = local.snap.version
}

output "published" {
  description = "False while Xshield has published nothing for the account and region, when the module creates nothing and sends no receipt."
  value       = local.snap.published
}

output "exclusive_rules_enabled" {
  description = "Whether each security group this module creates holds only the rules the snapshot declares for it, so the next apply removes a rule added outside Terraform. The receipt tells Xshield the same."
  value       = var.enable_exclusive_rules
}

output "summary" {
  description = "What the applied version holds, for plan review and run logs."
  value = {
    published                   = local.snap.published
    version                     = local.snap.version
    security_groups             = length(local.snap.security_groups)
    rules                       = length(local.snap.ingress_rules) + length(local.snap.egress_rules)
    interface_attachments       = length(local.snap.interface_attachments)
    attached_by_owner           = sort(keys(local.snap.directory_entries))
    withdrawing_security_groups = local.snap.withdrawing_security_groups
  }
}

output "review" {
  description = "What the applied version holds, as sentences: whose each group is, what its rules allow, and a closing count. Export it from the root module and a plan shows a change in words under Changes to Outputs."
  value       = local.review
}

output "security_group_ids" {
  description = "Each Xshield asset's security group ID, keyed by Xshield asset ID. Null for an asset whose group was refused, or an instance whose policy holds no rule."
  value       = { for id, asset in local.snap.assets : id => asset.security_group == null ? null : aws_security_group.this[asset.security_group].id }
}

output "attachment_keys" {
  description = "The interface attachments this run declares, by snapshot key: the snapshot's, less any whose interface no longer exists or has no room. The recovery and hand-over import blocks import only these."
  value       = keys(local.attachments_with_room)
}

output "directory_entries" {
  description = "The SSM parameter each owning workspace's aws-group-lookup reads, keyed by handle."
  value       = { for handle, entry in local.snap.directory_entries : handle => entry.parameter_name }
}

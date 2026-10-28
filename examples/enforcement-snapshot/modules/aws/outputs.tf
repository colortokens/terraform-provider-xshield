output "version" {
  description = "Snapshot version this configuration applies. Null while Xshield has published nothing for the account and region."
  value       = local.snap.version
}

output "published" {
  description = "False while Xshield has published nothing for the account and region, when the module creates nothing and sends no receipt."
  value       = local.snap.published
}

output "summary" {
  description = "What the applied version holds, for plan review and run logs."
  value = {
    published             = local.snap.published
    version               = local.snap.version
    security_groups       = length(local.snap.security_groups)
    rules                 = length(local.snap.ingress_rules) + length(local.snap.egress_rules)
    interface_attachments = length(local.snap.interface_attachments)
    attached_by_owner     = sort(keys(local.snap.directory))
    withdrawing           = local.snap.withdrawing
  }
}

output "security_group_ids" {
  description = "Each Xshield asset's security group ID, keyed by Xshield asset ID. Null for an asset whose policy holds no rule or was refused."
  value       = { for id, asset in local.snap.assets : id => asset.security_group == null ? null : aws_security_group.this[asset.security_group].id }
}

output "directory" {
  description = "The SSM parameter each owning workspace's group-lookup reads, keyed by handle."
  value       = { for handle, entry in local.snap.directory : handle => entry.parameter_name }
}

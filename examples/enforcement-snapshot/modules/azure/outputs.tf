output "version" {
  description = "Snapshot version this configuration applies. Null while Xshield has published nothing for the subscription and region."
  value       = local.snap.version
}

output "published" {
  description = "False while Xshield has published nothing for the subscription and region, when the module creates nothing."
  value       = local.snap.published
}

output "exclusive_rules_enabled" {
  description = "Whether each network security group this module creates holds only the rules the snapshot declares for it, so the next apply removes a rule added outside Terraform."
  value       = var.enable_exclusive_rules
}

output "summary" {
  description = "What the applied version holds, for plan review and run logs."
  value = {
    published               = local.snap.published
    version                 = local.snap.version
    network_security_groups = length(local.snap.network_security_groups)
    security_rules          = sum(concat([0], [for group in values(local.snap.network_security_groups) : length(group.security_rules)]))
    interface_associations  = length(local.snap.interface_associations)
    subnet_associations     = length(local.snap.subnet_associations)
  }
}

output "review" {
  description = "What the applied version holds, as sentences: where each group is associated and for which assets, what its rules allow and deny in the order Azure applies them, and a closing count. Export it from the root module and a plan shows a change in words under Changes to Outputs."
  value       = local.review
}

output "network_security_group_ids" {
  description = "The IDs of each Xshield asset's network security groups, keyed by Xshield asset ID. Empty for an asset that was refused, or whose policy writes no rule."
  value       = { for id, asset in local.snap.assets : id => [for key in asset.network_security_groups : local.network_security_group_ids[key]] }
}

output "interface_association_keys" {
  description = "The network interface associations this run declares, by snapshot key: the snapshot's, less any whose network interface no longer exists."
  value       = keys(local.interface_associations)
}

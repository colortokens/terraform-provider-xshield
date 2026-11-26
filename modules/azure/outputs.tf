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

output "subnet_association_keys" {
  description = "As interface_association_keys, for subnet associations: the snapshot's, less any whose subnet no longer exists."
  value       = keys(local.subnet_associations)
}

output "kept_interface_association_imports" {
  description = "The import ID of each network interface association the module keeps for a group of yours or the cloud connector's, by snapshot key: one Xshield holds, or one of a contained workload, on an interface that still exists. The receipt leaves them out, so the recovery-azure example imports them from here."
  value       = { for key, association in merge(local.held_interfaces, local.contained_interfaces) : key => "${association.level_id}|${association.network_security_group_id}" }
}

output "kept_subnet_association_imports" {
  description = "As kept_interface_association_imports, for a subnet association, whose import ID is the subnet's ID."
  value       = { for key, association in merge(local.held_subnets, local.contained_subnets) : key => association.level_id }
}

output "customer_security_rule_imports" {
  description = "The import ID of each of Xshield's rules the module adds to a group of yours, `<group ID>/securityRules/<rule name>`, by its key in `azurerm_network_security_rule.customer`. The receipt leaves them out, so the recovery-azure example imports them from here."
  value       = { for key, rule in local.customer_security_rules : key => "${local.customer_network_security_groups[split("/", key)[0]].id}/securityRules/${rule.name}" }
}

output "handover_interface_association_imports" {
  description = "The import ID of each network interface association the cloud connector has handed over, by snapshot key: where the connector has put Xshield's group in place of its own. The import blocks of handover.tf take them into the state."
  value = {
    for key, association in local.handed_over_interfaces : key => "${association.network_interface_id}|${local.network_security_group_ids[association.network_security_group]}"
    if local.handover_interface_groups[key] != "-"
  }
}

output "handover_subnet_association_imports" {
  description = "As handover_interface_association_imports, for a subnet association, whose import ID is the subnet's ID."
  value       = { for key, association in local.handed_over_subnets : key => association.subnet_id if local.handover_subnet_groups[key] != "-" }
}

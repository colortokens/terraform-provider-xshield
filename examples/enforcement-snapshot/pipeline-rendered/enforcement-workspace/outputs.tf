output "snapshot_version" {
  description = "Enforcement snapshot version this account is converged to."
  value       = data.xshield_enforcement_snapshot.this.version
}

output "snapshot_content_hash" {
  description = "Content hash of the applied snapshot. Sentinel verifies planned resources carry this value; the apply receipt reports it back to Xshield."
  value       = data.xshield_enforcement_snapshot.this.content_hash
}

output "quarantined_assets" {
  description = "Assets whose policy cannot be expressed by their segment. Their rules are NOT rendered (fail-secure); resolve with exception segments in Xshield."
  value       = data.xshield_enforcement_snapshot.this.quarantined_assets
}

output "group_security_groups" {
  description = "Composed security group per enforcement group."
  value       = { for slug, sg in aws_security_group.group : slug => sg.id }
}

output "marker_security_groups" {
  description = "Marker (membership token) security groups."
  value       = { for slug, sg in aws_security_group.marker : slug => sg.id }
}

output "address_sets" {
  description = "Managed prefix lists rendered for the snapshot's address sets."
  value       = { for slug, pl in aws_ec2_managed_prefix_list.pl : slug => pl.id }
}

output "workload_directory_paths" {
  description = "Directory paths application teams resolve against using their own tags."
  value       = [for e in data.xshield_enforcement_snapshot.this.directory : e.path]
}

output "apply_receipt_id" {
  description = "Receipt Xshield recorded for this apply, binding each snapshot construct to the resource created for it."
  value       = xshield_enforcement_receipt.this.id
}

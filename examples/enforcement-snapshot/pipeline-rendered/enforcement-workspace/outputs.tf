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

output "prefix_lists" {
  description = "Managed prefix lists rendered for off-cloud peers."
  value       = { for slug, pl in aws_ec2_managed_prefix_list.pl : slug => pl.id }
}

output "workload_directory_paths" {
  description = "Directory paths application teams resolve against using their own tags."
  value       = [for e in data.xshield_enforcement_snapshot.this.directory : e.path]
}

# The rendered-resource map an apply receipt should report back to Xshield so
# the platform can bind snapshot -> real AWS resource IDs.
output "apply_receipt_resource_map" {
  description = "Rendered resource identities for the apply receipt posted to Xshield."
  value = {
    version      = data.xshield_enforcement_snapshot.this.version
    content_hash = data.xshield_enforcement_snapshot.this.content_hash
    account_id   = var.cloud_account_id
    region       = var.region
    groups       = { for slug, sg in aws_security_group.group : slug => { (var.vpc_id) = sg.id } }
    markers      = { for slug, sg in aws_security_group.marker : slug => sg.id }
    prefix_lists = { for slug, pl in aws_ec2_managed_prefix_list.pl : slug => pl.id }
    directory    = { for p, param in aws_ssm_parameter.directory : p => param.version }
  }
}

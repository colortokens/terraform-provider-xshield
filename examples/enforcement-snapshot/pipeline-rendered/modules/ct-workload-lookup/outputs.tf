output "security_group_ids" {
  description = "ColorTokens security groups this workload must attach (composed group + any marker groups). Concat onto your base security groups."
  value       = local.security_group_ids
  depends_on  = [terraform_data.resolution_gate]
}

output "group" {
  description = "Enforcement group slug the workload resolved to (informational; do not build logic on it)."
  value       = local.entry != null ? try(local.entry.group, null) : null
}

output "resolved_path" {
  description = "Directory path that matched, deepest-first. Useful in plan output and support tickets."
  value       = local.resolved_path
}

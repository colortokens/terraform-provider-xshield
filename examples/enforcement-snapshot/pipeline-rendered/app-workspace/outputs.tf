output "resolved_group" {
  description = "Enforcement group the workload's tags resolved to."
  value       = module.ct.group
}

output "resolved_directory_path" {
  description = "Directory path that matched (deepest-first)."
  value       = module.ct.resolved_path
}

output "attached_security_groups" {
  description = "All security groups attached to the workload."
  value       = aws_instance.app.vpc_security_group_ids
}

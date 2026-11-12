output "changed" {
  description = "Whether an approved Full control change applies to the group."
  value       = local.changed
}

output "revoked_rules" {
  description = "Declared rules Xshield has left out, as ingress/<key> or egress/<key>."
  value       = local.changed ? data.xshield_aws_security_group_rules.this[0].revoked_rules : []
}

output "pending_rules" {
  description = "Declared rules an approved change will leave out once every workload that keeps them carries its cohort."
  value       = local.changed ? data.xshield_aws_security_group_rules.this[0].pending_rules : []
}

output "ingress_keys" {
  description = "Keys of the ingress rules declared now; adopt existing rules only under these, so a revoked rule's import never outlives it."
  value       = keys(local.ingress)
}

output "egress_keys" {
  description = "Keys of the egress rules declared now; adopt existing rules only under these."
  value       = keys(local.egress)
}

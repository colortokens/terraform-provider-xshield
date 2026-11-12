output "security_group_ids" {
  description = "Security group IDs to add to the resource's own list. Empty while Xshield lists no entry for the resource."
  value       = local.entry.security_group_ids

  precondition {
    condition     = local.entry.handle == local.handle
    error_message = "The directory entry at ${local.parameter_name} is for ${local.entry.handle}, not ${local.handle}. Only the enforcement workspace should write under ${var.directory_prefix}."
  }
  precondition {
    condition     = var.own_security_group_ids == null || local.slot_limit == null || length(coalesce(var.own_security_group_ids, [])) + length(local.entry.security_group_ids) <= coalesce(local.slot_limit, 0)
    error_message = "${local.handle} would carry ${length(coalesce(var.own_security_group_ids, []))} security groups of its own and ${length(local.entry.security_group_ids)} of Xshield's, more than the ${coalesce(local.slot_limit, 0)} AWS allows on it. Remove one of its own groups, or raise the quota where AWS allows it."
  }
}

output "own_security_groups_allowed" {
  description = "How many security groups of its own the resource can carry beside Xshield's: the limit AWS sets for it, as Xshield last discovered it, less the groups this lookup returns. Null until Xshield has discovered the limit."
  value       = local.slot_limit == null ? null : max(local.slot_limit - length(local.entry.security_group_ids), 0)
}

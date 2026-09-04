# Check a criteria and see how many assets it selects before creating a segment.
data "xshield_criteria" "payroll_db" {
  criteria = "application = 'payroll' AND role = 'db'"
}

output "member_count" {
  value = data.xshield_criteria.payroll_db.matching_assets
}

# The form a segment would store, with the managedby clause the backend appends.
output "as_a_segment_would_store_it" {
  value = data.xshield_criteria.payroll_db.canonical_segment_criteria
}

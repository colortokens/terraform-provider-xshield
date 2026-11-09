# Set to mandatory to stop such a plan; it fails only on rules the plan itself adds.
policy "xshield_reopened_access" {
  query             = "data.terraform.policies.xshield_reopened_access.deny"
  enforcement_level = "advisory"
}

# Keep advisory: it reports on every plan while a revert waits.
policy "xshield_revert_waiting" {
  query             = "data.terraform.policies.xshield_revert_waiting.warn"
  enforcement_level = "advisory"
}

# Set to mandatory to stop such a plan; it fails only on rules the plan itself deletes or changes.
policy "xshield_removed_early" {
  query             = "data.terraform.policies.xshield_removed_early.deny"
  enforcement_level = "advisory"
}

import "module" "xshield" {
  source = "./xshield-functions.sentinel"
}

# Set to soft-mandatory to stop such a plan; it fails only on rules the plan itself adds.
policy "xshield-reopened-access" {
  source            = "./xshield-reopened-access.sentinel"
  enforcement_level = "advisory"
}

# Keep advisory: it reports on every plan while a revert waits.
policy "xshield-revert-waiting" {
  source            = "./xshield-revert-waiting.sentinel"
  enforcement_level = "advisory"
}

# Set to soft-mandatory to stop such a plan; it fails only on rules the plan itself deletes or changes.
policy "xshield-removed-early" {
  source            = "./xshield-removed-early.sentinel"
  enforcement_level = "advisory"
}

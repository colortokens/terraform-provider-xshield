# For the workspace that runs the monitor. Set to soft-mandatory to stop a run on any failed Xshield check;
# the monitor's warn_on list then chooses what stops it.
policy "xshield-checks" {
  source            = "./xshield-checks.sentinel"
  enforcement_level = "advisory"
}

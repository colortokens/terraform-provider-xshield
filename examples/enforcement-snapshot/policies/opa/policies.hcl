# For the workspace that runs the monitor. Set to mandatory to stop a run on any failed Xshield check;
# the monitor's warn_on list then chooses what stops it.
policy "xshield_checks" {
  query             = "data.terraform.policies.xshield_checks.warn"
  enforcement_level = "advisory"
}

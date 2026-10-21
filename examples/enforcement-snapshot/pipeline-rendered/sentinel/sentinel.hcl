# ColorTokens enforcement policy set.
#
# Attachment guidance:
#   * ct-namespace-guard and ct-no-world-open-admin-ports -> attach ORG-WIDE
#     (every workspace). They are the only policies application teams meet.
#   * everything else -> attach to the account enforcement workspaces
#     (workspace name prefix ct-enforcement-*).
#
# Enforcement levels are deliberate:
#   hard-mandatory = no override path (mass deletion, namespace ownership,
#                    world-open administrative ports)
#   soft-mandatory = override requires an explicit approval from a policy owner
#   advisory       = surfaces in the run, never blocks

module "ct-common" {
  source = "./ct-common.sentinel"
}

policy "ct-namespace-guard" {
  source            = "./ct-namespace-guard.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "ct-no-world-open-admin-ports" {
  source            = "./ct-no-world-open-admin-ports.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "ct-mass-delete-guard" {
  source            = "./ct-mass-delete-guard.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "ct-snapshot-integrity" {
  source            = "./ct-snapshot-integrity.sentinel"
  enforcement_level = "soft-mandatory"
}

# Needs the http import and a bearer-token read of the expected version.
policy "ct-version-integrity" {
  source            = "./ct-version-integrity.sentinel"
  enforcement_level = "soft-mandatory"
}

policy "ct-conformance-watch" {
  source            = "./ct-conformance-watch.sentinel"
  enforcement_level = "advisory"
}

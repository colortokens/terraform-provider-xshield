# ColorTokens enforcement policy set.
#
# Attachment guidance:
#   * ct-namespace-guard  -> attach ORG-WIDE (every workspace). It is the only
#     policy application teams ever encounter, and the only one that must never
#     be scoped narrowly.
#   * everything else     -> attach to the account enforcement workspaces
#     (workspace name prefix ct-enforcement-*).
#
# Enforcement levels are deliberate:
#   hard-mandatory = no override path (mass deletion, namespace ownership)
#   soft-mandatory = override requires an explicit approval from a policy owner
#   advisory       = surfaces in the run, never blocks

policy "ct-namespace-guard" {
  source            = "./ct-namespace-guard.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "ct-mass-delete-guard" {
  source            = "./ct-mass-delete-guard.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "ct-provenance" {
  source            = "./ct-provenance.sentinel"
  enforcement_level = "soft-mandatory"
}

# Start advisory during brownfield coexistence, raise to soft-mandatory once
# the account completes the prune phase.
policy "ct-version-integrity" {
  source            = "./ct-version-integrity.sentinel"
  enforcement_level = "soft-mandatory"
}

policy "ct-conformance-watch" {
  source            = "./ct-conformance-watch.sentinel"
  enforcement_level = "advisory"
}

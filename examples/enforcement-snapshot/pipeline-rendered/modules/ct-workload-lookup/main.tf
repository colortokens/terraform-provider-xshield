# =============================================================================
# ct-workload-lookup - the ONLY ColorTokens surface application teams touch.
#
# Resolves the security groups a workload must attach, using nothing but the
# tags the workload already carries under the org tagging standard.
#
# Deliberately contains NO ColorTokens provider, credential, endpoint, segment
# name, or policy version. It is plain AWS: one SSM read plus local matching.
# Renaming or reorganising segments in Xshield cannot break a caller.
#
# Semantics:
#   * DEEPEST MATCH WINS  - env/app/tier beats env/app beats env, mirroring
#     segment hierarchy (most-specific segment governs).
#   * STRICT KEY ORDER    - a missing middle key stops path building; it can
#     never silently collapse to a deeper path and bind the wrong groups.
#   * FAIL CLOSED         - no match is a hard plan error, not an unprotected
#     deploy (set strict=false only for deliberate staged migration).
# =============================================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# One read of the whole namespace; matching happens locally so probing candidate
# paths never produces failed reads.
data "aws_ssm_parameters_by_path" "directory" {
  path      = var.directory_prefix
  recursive = true
}

locals {
  # The SSM data source marks the whole values list sensitive; the directory
  # holds security-group IDs, not secrets. Unwrap the list itself: a for
  # expression over a sensitive list yields a sensitive result whatever it does
  # to each element.
  directory = zipmap(
    data.aws_ssm_parameters_by_path.directory.names,
    nonsensitive(data.aws_ssm_parameters_by_path.directory.values)
  )

  # Build the tag values in schema order, stopping at the first absent key.
  # {environment, tier} with no application yields ["prod"] - never "prod/db".
  ordered_values = [
    for i, k in var.tag_keys : var.tags[k]
    if alltrue([
      for j in slice(var.tag_keys, 0, i + 1) : contains(keys(var.tags), j) && trimspace(lookup(var.tags, j, "")) != ""
    ])
  ]

  # Deepest first.
  candidate_paths = [
    for i in range(length(local.ordered_values), 0, -1) :
    "${var.directory_prefix}/${join("/", slice(local.ordered_values, 0, i))}"
  ]

  matched       = [for p in local.candidate_paths : p if contains(keys(local.directory), p)]
  resolved_path = length(local.matched) > 0 ? local.matched[0] : null

  entry = local.resolved_path != null ? jsondecode(local.directory[local.resolved_path]) : null

  security_group_ids = local.entry != null ? concat(
    try(local.entry.sg_ids, []),
    try(local.entry.marker_sg_ids, []),
  ) : []
}

# Fail-closed gate. A precondition is a HARD error (unlike check{} warnings), so
# a workload whose tags bind to no segment cannot be deployed unprotected.
resource "terraform_data" "resolution_gate" {
  input = local.resolved_path

  lifecycle {
    precondition {
      condition = !var.strict || local.resolved_path != null
      error_message = join("", [
        "No ColorTokens directory entry matches tags ",
        jsonencode({ for k in var.tag_keys : k => lookup(var.tags, k, "<missing>") }),
        ". Tried (deepest first): ",
        join(", ", local.candidate_paths),
        ". Ask SecOps to bind a segment for this workload in Xshield. ",
        "Deploying without ColorTokens enforcement is not permitted (set strict=false only for a deliberate, time-boxed migration)."
      ])
    }

    precondition {
      condition     = length(local.ordered_values) > 0
      error_message = "None of the required tag keys ${jsonencode(var.tag_keys)} are present on this workload; the org tagging standard mandates at least the first key."
    }
  }
}

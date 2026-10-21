# =============================================================================
# MONITOR workspace - read-only enforcement health for one account x region.
#
# It creates nothing. Every check below reads what Xshield knows and warns when
# something needs a person:
#
#   * policy SecOps approved has waited too long for an enforcement run
#   * the enforcement pipeline has stopped running at all
#   * the cloud connector observes drift, grouped by who restores it
#
# Run it on a schedule. In HCP Terraform (Standard or Premium) and Terraform
# Enterprise, health assessments with continuous validation evaluate these
# checks between runs and notify; on any other runner, a scheduled
# `terraform plan -detailed-exitcode` does the same job.
# =============================================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    xshield = {
      source  = "colortokens/xshield"
      version = ">= 0.1.0"
    }
  }
}

provider "xshield" {
  server_url       = var.xshield_server_url
  tenancy_id       = var.xshield_tenancy_id
  user_id          = var.xshield_user_id
  fingerprint      = var.xshield_fingerprint
  private_key_path = var.xshield_private_key_path
}

data "xshield_enforcement_status" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.region
}

locals {
  status = data.xshield_enforcement_status.this

  pending_deadline = local.status.pending_since == null ? null : timeadd(local.status.pending_since, "${var.max_pending_hours}h")
  pending_too_long = local.status.state == "pending" && local.pending_deadline != null && timecmp(plantimestamp(), local.pending_deadline) > 0

  heartbeat_deadline = local.status.last_checked_at == null ? null : timeadd(local.status.last_checked_at, "${var.max_silence_hours}h")
  pipeline_silent    = local.heartbeat_deadline != null && timecmp(plantimestamp(), local.heartbeat_deadline) > 0

  findings_by_owner = {
    for owner in ["pipeline", "manual", "workload"] :
    owner => [for f in local.status.drift_findings : "${f.kind} ${f.resource}: ${f.detail}" if f.restoration == owner]
  }
}

check "approved_policy_is_enforced" {
  assert {
    condition     = !local.pending_too_long
    error_message = "Approved policy has waited more than ${var.max_pending_hours}h for an enforcement run (pending since ${coalesce(local.status.pending_since, "unknown")}): ${length(local.status.pending_rules_added)} rule(s) to add, ${length(local.status.pending_rules_removed)} to remove. Run the enforcement pipeline."
  }
}

check "enforcement_pipeline_is_running" {
  assert {
    condition     = !local.pipeline_silent
    error_message = "No enforcement plan has resolved policy for ${var.max_silence_hours}h (last at ${coalesce(local.status.last_checked_at, "never")}). The pipeline has stopped running, so drift and new policy are not being converged."
  }
}

check "no_drift_the_next_run_repairs" {
  assert {
    condition     = length(local.findings_by_owner["pipeline"]) == 0
    error_message = "Drift the next enforcement run will repair: ${join("; ", local.findings_by_owner["pipeline"])}"
  }
}

check "no_drift_needing_a_person" {
  assert {
    condition     = length(local.findings_by_owner["manual"]) == 0
    error_message = "Drift Terraform cannot repair - remove by hand and find how it was added: ${join("; ", local.findings_by_owner["manual"])}"
  }
}

check "workloads_attached_correctly" {
  assert {
    condition     = length(local.findings_by_owner["workload"]) == 0
    error_message = "Workloads whose attachment the application team must fix: ${join("; ", local.findings_by_owner["workload"])}"
  }
}

output "enforcement_health" {
  description = "Convergence and drift at a glance."
  value = {
    state            = local.status.state
    expected_version = local.status.expected_version
    applied_version  = local.status.applied_version
    pending_since    = local.status.pending_since
    last_checked_at  = local.status.last_checked_at
    drift_evaluated  = local.status.drift_evaluated
    drift_by_owner   = { for owner, items in local.findings_by_owner : owner => length(items) }
  }
}

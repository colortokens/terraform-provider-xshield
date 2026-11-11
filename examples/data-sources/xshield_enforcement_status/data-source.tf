# Two of the problems examples/enforcement-snapshot/monitor reports, each as a named check with the monitor's
# own condition. The monitor is the full version: every problem, including policy that has never been applied,
# a list of what is waiting, each limit as a variable, and a fail_on list that stops a plan.
data "xshield_enforcement_status" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

locals {
  status        = data.xshield_enforcement_status.this
  where         = "${local.status.cloud_account_id}/${local.status.region}"
  max_apply_age = "24h"

  drift_high = [
    for f in local.status.drift_findings : "  ${f.kind} ${coalesce(f.resource_name, f.resource)}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "high"
  ]

  # coalesce keeps a null time out of timeadd while nothing is pending.
  apply_overdue = local.status.state == "pending" && timecmp(timeadd(coalesce(local.status.pending_since, plantimestamp()), local.max_apply_age), plantimestamp()) < 0
}

check "xshield_drift_high" {
  assert {
    condition     = length(local.drift_high) == 0
    error_message = join("\n", concat(["Xshield sees high-severity drift in ${local.where}:"], local.drift_high))
  }
}

check "xshield_apply_overdue" {
  assert {
    condition = !local.apply_overdue
    error_message = join("\n", [
      "Approved Xshield policy for ${local.where} has waited more than ${local.max_apply_age} for an enforcement run:",
      "  waiting since ${coalesce(local.status.pending_since, "an unknown time")}: ${length(local.status.pending_security_groups_added)} group(s) to create, ${length(local.status.pending_rules_added)} rule(s) to add, ${length(local.status.pending_rules_removed)} rule(s) to remove, ${length(local.status.pending_attachments_added)} attachment(s) to add. Run the enforcement workspace to apply them.",
    ])
  }
}

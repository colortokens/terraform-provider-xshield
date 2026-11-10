# Report enforcement problems in one account and region as named checks.
# examples/enforcement-snapshot/monitor is the full version: every problem,
# each limit as a variable, and a fail_on list that stops a plan.
data "xshield_enforcement_status" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

check "xshield_drift_high" {
  assert {
    condition = length([for f in data.xshield_enforcement_status.this.drift_findings : f if f.severity == "high"]) == 0
    error_message = join("\n", concat(["Xshield sees high-severity drift:"], [
      for f in data.xshield_enforcement_status.this.drift_findings : "  ${f.kind} ${coalesce(f.resource_name, f.resource)}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "high"
    ]))
  }
}

check "xshield_apply_overdue" {
  assert {
    # coalesce keeps a null time out of timeadd while nothing is pending.
    condition = (data.xshield_enforcement_status.this.state != "pending" ||
    timecmp(timeadd(coalesce(data.xshield_enforcement_status.this.pending_since, plantimestamp()), "24h"), plantimestamp()) > 0)
    error_message = "Approved Xshield policy has waited more than 24 hours for an enforcement run: ${length(data.xshield_enforcement_status.this.pending_rules_added)} rule(s) to add, ${length(data.xshield_enforcement_status.this.pending_rules_removed)} to remove."
  }
}

# Alert on drift and stalled pipelines from a check block. Checks run on every
# plan and, where the platform evaluates them on a schedule, between runs too.
check "xshield_enforcement_health" {
  data "xshield_enforcement_status" "this" {
    cloud_account_id = "123456789012"
    region           = "us-east-1"
  }

  assert {
    condition = length([
      for f in data.xshield_enforcement_status.this.drift_findings : f if f.severity == "high"
    ]) == 0
    error_message = "Xshield observes high-severity drift: ${join("; ", [
      for f in data.xshield_enforcement_status.this.drift_findings : "${f.kind} ${f.resource} (${f.restoration})" if f.severity == "high"
    ])}"
  }

  assert {
    condition     = data.xshield_enforcement_status.this.state != "pending" || timecmp(timeadd(data.xshield_enforcement_status.this.pending_since, "24h"), plantimestamp()) > 0
    error_message = "Approved policy has been waiting more than 24h for an enforcement run: ${length(data.xshield_enforcement_status.this.pending_rules_added)} rule(s) to add, ${length(data.xshield_enforcement_status.this.pending_rules_removed)} to remove."
  }
}

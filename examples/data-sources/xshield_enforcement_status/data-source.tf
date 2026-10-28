# Alert on drift, stalled pipelines and workloads Xshield could not enforce.
# Checks run on every plan and, where the platform evaluates them on a
# schedule, between runs too.
check "xshield_enforcement" {
  data "xshield_enforcement_status" "this" {
    cloud_account_id = "123456789012"
    region           = "us-east-1"
  }

  assert {
    condition = length([for f in data.xshield_enforcement_status.this.drift_findings : f if f.severity == "high"]) == 0
    error_message = join("\n", [
      for f in data.xshield_enforcement_status.this.drift_findings : "${f.kind} ${f.resource}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "high"
    ])
  }

  assert {
    condition     = data.xshield_enforcement_status.this.state != "pending" || timecmp(timeadd(data.xshield_enforcement_status.this.pending_since, "24h"), plantimestamp()) > 0
    error_message = "Approved policy has waited more than 24 hours for an enforcement run."
  }
}

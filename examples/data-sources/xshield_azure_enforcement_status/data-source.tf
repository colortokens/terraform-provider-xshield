# The snapshot leaves out a workload Xshield refuses, so a plan that changes nothing for it does not mean its
# policy is enforced. These checks report each refusal, high-severity drift the cloud connector observes, and a
# pipeline that has stopped resolving the expected version.
data "xshield_azure_enforcement_status" "this" {
  cloud_account_id = "00000000-0000-0000-0000-000000000000"
  region           = "eastus2"
}

locals {
  status        = data.xshield_azure_enforcement_status.this
  where         = "${local.status.cloud_account_id}/${local.status.region}"
  max_check_age = "24h"
  refused       = [for n in local.status.notices : "  ${coalesce(n.asset_name, n.asset_id)}: ${n.reason}: ${n.message}" if n.code == "assetRefused"]
  drift_high = [
    for f in local.status.drift_findings : "  ${f.kind} ${coalesce(f.resource_name, f.resource)}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "high"
  ]
  pipeline_stale = local.status.published && timecmp(timeadd(coalesce(local.status.last_checked_at, "1970-01-01T00:00:00Z"), local.max_check_age), plantimestamp()) < 0
}

check "xshield_workloads_refused" {
  assert {
    condition     = length(local.refused) == 0
    error_message = join("\n", concat(["Xshield cannot enforce policy on these workloads in ${local.where}:"], local.refused))
  }
}

check "xshield_drift_high" {
  assert {
    condition     = length(local.drift_high) == 0
    error_message = join("\n", concat(["Xshield sees high-severity drift in ${local.where}:"], local.drift_high))
  }
}

check "xshield_pipeline_stale" {
  assert {
    condition     = !local.pipeline_stale
    error_message = "No enforcement plan for ${local.where} has resolved the version Xshield expects in the last ${local.max_check_age}: run the enforcement workspace."
  }
}

# Alerts on drift, stalled pipelines and workloads Xshield could not enforce,
# from a check block. Where checks run on a schedule, such as HCP Terraform
# continuous validation, it alerts between runs too.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

provider "xshield" {}

variable "cloud_account_id" {
  type = string
}

variable "region" {
  type = string
}

check "xshield_enforcement" {
  data "xshield_enforcement_status" "this" {
    cloud_account_id = var.cloud_account_id
    region           = var.region
  }

  assert {
    condition = length([for f in data.xshield_enforcement_status.this.drift_findings : f if f.severity == "high"]) == 0
    error_message = join("\n", concat(["Xshield sees high-severity drift in ${var.cloud_account_id}/${var.region}:"], [
      for f in data.xshield_enforcement_status.this.drift_findings : "  ${f.kind} ${f.resource}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "high"
    ]))
  }

  assert {
    condition     = data.xshield_enforcement_status.this.state != "pending" || timecmp(timeadd(data.xshield_enforcement_status.this.pending_since, "24h"), plantimestamp()) > 0
    error_message = "Approved Xshield policy has waited more than 24 hours for an enforcement run: ${length(data.xshield_enforcement_status.this.pending_rules_added)} rule(s) to add."
  }

  assert {
    # A contained workload and a group being withdrawn are deliberate states, not failures.
    condition = length([for n in data.xshield_enforcement_status.this.notices : n if contains(["assetRefused", "groupRefused"], n.code)]) == 0
    error_message = join("\n", concat(["Xshield could not enforce every workload in ${var.cloud_account_id}/${var.region}:"], [
      for n in data.xshield_enforcement_status.this.notices : "  ${coalesce(n.asset_id, n.group, "-")}: ${n.message}${n.reason == null ? "" : " (${n.reason})"}" if contains(["assetRefused", "groupRefused"], n.code)
    ]))
  }
}

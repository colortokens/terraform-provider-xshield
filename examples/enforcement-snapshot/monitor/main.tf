# Reports what is wrong with Xshield enforcement in one account and region.
#
# Each problem has a name and a check of its own, so a plan says exactly what
# it found. A check only warns. Name a problem in fail_on and the plan stops
# on it instead, with no other tooling. Run this on a schedule, or where
# checks are evaluated between runs, such as HCP Terraform continuous
# validation. It manages no resources, so -detailed-exitcode says nothing
# here: read the warnings, the problems output, or use fail_on.
#
#   drift_high             the cloud differs from what was applied, and access may be wider than approved
#   drift_medium           the cloud differs in a way the next enforcement apply restores (not warned by default)
#   workload_not_enforced  Xshield could not write a group for a workload
#   apply_overdue          newer approved policy has waited longer than max_apply_age for an enforcement run
#   never_applied          published policy has never been applied, for longer than max_apply_age
#   owner_apply_overdue    a Full control change has waited longer than max_owner_apply_age for the workspace
#                          that owns a customer security group
#   pipeline_stopped       no enforcement plan has run for longer than max_run_gap
#   drift_not_evaluated    Xshield has not looked for drift since the last apply, for longer than max_unobserved_age
#   port_not_narrowed      a port is still deployed in Xshield, but the Full control change that narrowed its
#                          customer security group was reverted, so the group allows more than the policy
#   unpublished            Xshield has published nothing here: wrong tenant, or the account is not onboarded
#                          (not warned by default)

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
  description = "AWS account to report on."
  type        = string
}

variable "region" {
  description = "AWS region to report on."
  type        = string
}

variable "warn_on" {
  description = "Problems to warn about. See the list at the top of this file."
  type        = set(string)
  default = [
    "drift_high", "workload_not_enforced", "apply_overdue", "never_applied", "owner_apply_overdue",
    "pipeline_stopped", "drift_not_evaluated", "port_not_narrowed",
  ]

  validation {
    condition = length(setsubtract(var.warn_on, [
      "drift_high", "drift_medium", "workload_not_enforced", "apply_overdue", "never_applied", "owner_apply_overdue",
      "pipeline_stopped", "drift_not_evaluated", "port_not_narrowed", "unpublished",
    ])) == 0
    error_message = "The warn_on list names a problem this monitor does not know. Use the names listed at the top of main.tf."
  }
}

variable "fail_on" {
  description = "Problems that stop the plan. Empty by default: nothing here blocks a pipeline unless you name it."
  type        = set(string)
  default     = []

  validation {
    condition = length(setsubtract(var.fail_on, [
      "drift_high", "drift_medium", "workload_not_enforced", "apply_overdue", "never_applied", "owner_apply_overdue",
      "pipeline_stopped", "drift_not_evaluated", "port_not_narrowed", "unpublished",
    ])) == 0
    error_message = "The fail_on list names a problem this monitor does not know. Use the names listed at the top of main.tf."
  }
}

variable "max_apply_age" {
  description = "How long approved policy may wait for an enforcement run, as a duration such as 24h."
  type        = string
  default     = "24h"

  validation {
    condition     = can(timeadd("2020-01-01T00:00:00Z", var.max_apply_age))
    error_message = "The max_apply_age value must be a duration such as 24h or 90m."
  }
}

variable "max_owner_apply_age" {
  description = "How long a Full control change may wait for the workspace that owns a customer security group."
  type        = string
  default     = "24h"

  validation {
    condition     = can(timeadd("2020-01-01T00:00:00Z", var.max_owner_apply_age))
    error_message = "The max_owner_apply_age value must be a duration such as 24h or 90m."
  }
}

variable "max_run_gap" {
  description = "How long the enforcement workspace may go without planning. Raise it if that pipeline runs only on a change."
  type        = string
  default     = "72h"

  validation {
    condition     = can(timeadd("2020-01-01T00:00:00Z", var.max_run_gap))
    error_message = "The max_run_gap value must be a duration such as 72h."
  }
}

variable "max_unobserved_age" {
  description = "How long after an apply Xshield may go without evaluating drift."
  type        = string
  default     = "24h"

  validation {
    condition     = can(timeadd("2020-01-01T00:00:00Z", var.max_unobserved_age))
    error_message = "The max_unobserved_age value must be a duration such as 24h."
  }
}

data "xshield_enforcement_status" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.region
}

locals {
  status = data.xshield_enforcement_status.this
  where  = "${var.cloud_account_id}/${var.region}"
  now    = plantimestamp()
  shown  = 20

  # coalesce keeps a null time out of timeadd; each use also tests the state or the null itself.
  pending_overdue = timecmp(timeadd(coalesce(local.status.pending_since, local.now), var.max_apply_age), local.now) < 0
  run_overdue     = timecmp(timeadd(coalesce(local.status.last_checked_at, local.now), var.max_run_gap), local.now) < 0
  unobserved      = timecmp(timeadd(coalesce(local.status.applied_at, local.now), var.max_unobserved_age), local.now) < 0

  pending = concat(
    [for key in local.status.pending_security_groups_added : "  create group ${key}"],
    [for key in local.status.pending_rules_added : "  add rule ${key}"],
    [for key in local.status.pending_rules_removed : "  remove rule ${key}"],
    [for key in local.status.pending_attachments_added : "  attach ${key}"],
  )
  pending_lines = concat(
    ["  waiting since ${coalesce(local.status.pending_since, "an unknown time")}: ${length(local.status.pending_security_groups_added)} group(s) to create, ${length(local.status.pending_rules_added)} rule(s) to add, ${length(local.status.pending_rules_removed)} rule(s) to remove, ${length(local.status.pending_attachments_added)} attachment(s) to add. Run the enforcement workspace to apply them."],
    slice(local.pending, 0, min(local.shown, length(local.pending))),
    length(local.pending) > local.shown ? ["  and ${length(local.pending) - local.shown} more"] : [],
  )

  # Notices that differ only in their workload share one line, which lists the workloads.
  overdue_held_notices = [
    for n in local.status.notices : merge(n, {
      label    = coalesce(n.group, n.asset_name, n.asset_id, "-")
      workload = coalesce(n.asset_name, n.asset_id, "-")
      cause    = jsonencode([coalesce(n.group, n.asset_name, n.asset_id, "-"), n.group, n.message, n.reason, n.since])
    })
    if n.code == "changeSetHeld" && (n.since == null || timecmp(timeadd(coalesce(n.since, local.now), var.max_owner_apply_age), local.now) < 0)
  ]
  overdue_held_by_cause = { for n in local.overdue_held_notices : n.cause => n... }
  overdue_held_causes = [
    for key in distinct(local.overdue_held_notices[*].cause) : merge(local.overdue_held_by_cause[key][0], {
      workloads = [for w in distinct(local.overdue_held_by_cause[key][*].workload) : w if !contains([local.overdue_held_by_cause[key][0].label, "-"], w)]
    })
  ]
  unnarrowed_port_notices = [
    for n in local.status.notices : merge(n, {
      workload = coalesce(n.asset_name, n.asset_id, "-")
      cause    = jsonencode([n.group, n.message, n.reason, n.since])
    })
    if n.code == "portNotNarrowed"
  ]
  unnarrowed_ports_by_cause = { for n in local.unnarrowed_port_notices : n.cause => n... }
  unnarrowed_port_causes = [
    for key in distinct(local.unnarrowed_port_notices[*].cause) : merge(local.unnarrowed_ports_by_cause[key][0], {
      workloads = distinct(local.unnarrowed_ports_by_cause[key][*].workload)
    })
  ]

  problems = tomap({
    drift_high = [
      for f in local.status.drift_findings : "  ${f.kind} ${coalesce(f.resource_name, f.resource)}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "high"
    ]
    drift_medium = [
      for f in local.status.drift_findings : "  ${f.kind} ${coalesce(f.resource_name, f.resource)}: ${f.detail} (fixed by: ${f.restoration})" if f.severity == "medium"
    ]
    workload_not_enforced = [
      for n in local.status.notices : "  ${coalesce(n.asset_name, n.asset_id, n.group, "-")}: ${n.message}${n.reason == null ? "" : " (${n.reason})"}" if contains(["assetRefused", "groupRefused"], n.code)
    ]
    apply_overdue = local.status.state == "pending" && local.pending_overdue ? local.pending_lines : []
    never_applied = local.status.state == "unapplied" && local.pending_overdue ? local.pending_lines : []
    owner_apply_overdue = [
      for c in local.overdue_held_causes :
      "  ${c.label}: ${c.message} (change set ${coalesce(c.reason, "unknown")}, waiting since ${coalesce(c.since, "an unknown time")}${length(c.workloads) == 0 ? "" : "; workloads: ${join(", ", c.workloads)}"})"
    ]
    pipeline_stopped = local.status.published && local.status.last_checked_at != null && local.run_overdue ? [
      "  last enforcement plan: ${coalesce(local.status.last_checked_at, "never")}. Until that workspace plans again, nothing new Xshield approves is applied and the state below may be stale.",
    ] : []
    drift_not_evaluated = local.status.applied_version != null && !local.status.drift_evaluated && local.unobserved ? [
      "  applied ${coalesce(local.status.applied_at, "at an unknown time")}; last observation ${coalesce(local.status.drift_observed_at, "none")}. No drift finding here means nobody looked, not that nothing drifted: check that the cloud connector's discovery is running.",
    ] : []
    port_not_narrowed = [
      for c in local.unnarrowed_port_causes : "  ${join(", ", c.workloads)}: ${c.message} (change set ${coalesce(c.reason, "unknown")}, reverted ${coalesce(c.since, "at an unknown time")})"
    ]
    unpublished = local.status.published ? [] : [
      "  check that the provider points at the right Xshield tenant, and that the account and region are onboarded for pipeline delivery.",
    ]
  })

  headlines = {
    drift_high            = "Xshield sees high-severity drift in ${local.where}:"
    drift_medium          = "Xshield sees medium-severity drift in ${local.where}:"
    workload_not_enforced = "Xshield could not enforce every workload in ${local.where}:"
    apply_overdue         = "Approved Xshield policy for ${local.where} has waited more than ${var.max_apply_age} for an enforcement run:"
    never_applied         = "Xshield policy for ${local.where} was published more than ${var.max_apply_age} ago and has never been applied:"
    owner_apply_overdue   = "A Full control change in ${local.where} has waited more than ${var.max_owner_apply_age} for the workspace that owns a customer security group:"
    pipeline_stopped      = "No enforcement plan has run for ${local.where} in more than ${var.max_run_gap}:"
    drift_not_evaluated   = "Xshield has not evaluated drift in ${local.where} for more than ${var.max_unobserved_age} since the last apply:"
    port_not_narrowed     = "Ports are deployed in Xshield in ${local.where} whose customer security group is no longer narrowed for them:"
    unpublished           = "Xshield has published nothing for ${local.where}:"
  }

  failing = sort([for name in var.fail_on : name if length(local.problems[name]) > 0])
}

check "xshield_drift_high" {
  assert {
    condition     = !contains(var.warn_on, "drift_high") || length(local.problems.drift_high) == 0
    error_message = join("\n", concat([local.headlines.drift_high], local.problems.drift_high))
  }
}

check "xshield_drift_medium" {
  assert {
    condition     = !contains(var.warn_on, "drift_medium") || length(local.problems.drift_medium) == 0
    error_message = join("\n", concat([local.headlines.drift_medium], local.problems.drift_medium))
  }
}

check "xshield_workload_not_enforced" {
  assert {
    # A contained workload and a group being withdrawn are deliberate states, not failures.
    condition     = !contains(var.warn_on, "workload_not_enforced") || length(local.problems.workload_not_enforced) == 0
    error_message = join("\n", concat([local.headlines.workload_not_enforced], local.problems.workload_not_enforced))
  }
}

check "xshield_apply_overdue" {
  assert {
    condition     = !contains(var.warn_on, "apply_overdue") || length(local.problems.apply_overdue) == 0
    error_message = join("\n", concat([local.headlines.apply_overdue], local.problems.apply_overdue))
  }
}

check "xshield_never_applied" {
  assert {
    condition     = !contains(var.warn_on, "never_applied") || length(local.problems.never_applied) == 0
    error_message = join("\n", concat([local.headlines.never_applied], local.problems.never_applied))
  }
}

check "xshield_owner_apply_overdue" {
  assert {
    condition     = !contains(var.warn_on, "owner_apply_overdue") || length(local.problems.owner_apply_overdue) == 0
    error_message = join("\n", concat([local.headlines.owner_apply_overdue], local.problems.owner_apply_overdue))
  }
}

check "xshield_pipeline_stopped" {
  assert {
    condition     = !contains(var.warn_on, "pipeline_stopped") || length(local.problems.pipeline_stopped) == 0
    error_message = join("\n", concat([local.headlines.pipeline_stopped], local.problems.pipeline_stopped))
  }
}

check "xshield_drift_not_evaluated" {
  assert {
    condition     = !contains(var.warn_on, "drift_not_evaluated") || length(local.problems.drift_not_evaluated) == 0
    error_message = join("\n", concat([local.headlines.drift_not_evaluated], local.problems.drift_not_evaluated))
  }
}

check "xshield_port_not_narrowed" {
  assert {
    condition     = !contains(var.warn_on, "port_not_narrowed") || length(local.problems.port_not_narrowed) == 0
    error_message = join("\n", concat([local.headlines.port_not_narrowed], local.problems.port_not_narrowed))
  }
}

check "xshield_unpublished" {
  assert {
    condition     = !contains(var.warn_on, "unpublished") || length(local.problems.unpublished) == 0
    error_message = join("\n", concat([local.headlines.unpublished], local.problems.unpublished))
  }
}

output "problems" {
  description = "What is wrong now, by problem name, for every name in warn_on. Empty when nothing is."
  value = {
    for name, lines in local.problems : name => concat([local.headlines[name]], lines)
    if length(lines) > 0 && contains(var.warn_on, name)
  }

  precondition {
    condition = length(local.failing) == 0
    error_message = join("\n\n", [
      for name in local.failing : join("\n", concat([local.headlines[name]], local.problems[name]))
    ])
  }
}

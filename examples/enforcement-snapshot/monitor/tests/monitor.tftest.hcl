# terraform test, offline: each problem warns on what it should, stays quiet
# otherwise, says what a reader needs, and stops the plan only when named in
# fail_on. The Xshield provider is mocked. A time in 2020 is long ago; one in
# 2999 stands for "just now", since the checks compare with the plan's time.

mock_provider "xshield" {
  mock_data "xshield_enforcement_status" {
    defaults = {
      published                     = true
      state                         = "converged"
      expected_version              = "v2"
      applied_version               = "v2"
      applied_at                    = "2020-01-01T00:00:00Z"
      last_checked_at               = "2999-01-01T00:00:00Z"
      pending_since                 = null
      pending_security_groups_added = []
      pending_rules_added           = []
      pending_rules_removed         = []
      pending_attachments_added     = []
      drift_evaluated               = true
      drift_observed_at             = "2020-01-02T00:00:00Z"
      drift_findings                = []
      notices = [
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "rds/old-db", since = null, message = "kept until discovery shows it detached" },
      ]
    }
  }
}

variables {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

run "quiet_when_converged" {
  command = plan

  assert {
    condition     = length(output.problems) == 0
    error_message = "A converged account with a group being withdrawn reported ${jsonencode(output.problems)}."
  }
}

run "quiet_when_nothing_is_published" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = false, state = "unpublished", expected_version = null, applied_version = null, applied_at = null, last_checked_at = null,
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = null, drift_findings = [], notices = []
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Nothing published is quiet unless unpublished is asked for, but reported ${jsonencode(output.problems)}."
  }
}

run "warns_that_nothing_is_published_when_asked" {
  command = plan

  variables {
    warn_on = ["unpublished"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = false, state = "unpublished", expected_version = null, applied_version = null, applied_at = null, last_checked_at = null,
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = null, drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_unpublished]
}

run "warns_on_high_severity_drift_and_not_on_medium" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline" },
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0b2", resource_name = null, key = "i-0b2/in/tcp/443/10.0.0.0/8", detail = "the rule is gone" },
      ]
    }
  }

  expect_failures = [check.xshield_drift_high]

  assert {
    condition = output.problems == {
      drift_high = [
        "Xshield sees high-severity drift in 123456789012/us-east-1:",
        "  ruleUnmanaged sgr-0a1: tcp 22 from 0.0.0.0/0 was added outside the pipeline (fixed by: manual)",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_on_medium_severity_drift_when_asked" {
  command = plan

  variables {
    warn_on = ["drift_medium"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0b2", resource_name = null, key = "i-0b2/in/tcp/443/10.0.0.0/8", detail = "the rule is gone" },
      ]
    }
  }

  expect_failures = [check.xshield_drift_medium]
}

run "warns_on_a_refused_workload" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "assetRefused", reason = "NO_FREE_SLOT", asset_id = "asset-web-1", asset_name = "i-0web1", group = null, since = null, message = "no Xshield group can be written for this workload as it stands" },
      ]
    }
  }

  expect_failures = [check.xshield_workload_not_enforced]

  assert {
    condition     = output.problems.workload_not_enforced[1] == "  i-0web1: no Xshield group can be written for this workload as it stands (NO_FREE_SLOT)"
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_approved_policy_has_waited_too_long_and_counts_everything_waiting" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published                 = true, state = "pending", expected_version = "v3", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since             = "2020-02-01T00:00:00Z", pending_security_groups_added = ["i-0new"], pending_rules_added = [], pending_rules_removed = ["i-0a1/in/tcp/22/10.0.0.0/8"],
      pending_attachments_added = ["i-0new/eni-0new"], drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_apply_overdue]

  assert {
    condition = output.problems == {
      apply_overdue = [
        "Approved Xshield policy for 123456789012/us-east-1 has waited more than 24h for an enforcement run:",
        "  waiting since 2020-02-01T00:00:00Z: 1 group(s) to create, 0 rule(s) to add, 1 rule(s) to remove, 1 attachment(s) to add. Run the enforcement workspace to apply them.",
        "  create group i-0new",
        "  remove rule i-0a1/in/tcp/22/10.0.0.0/8",
        "  attach i-0new/eni-0new",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "lists_twenty_waiting_changes_and_counts_the_rest" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published                     = true
      state                         = "pending"
      expected_version              = "v3"
      applied_version               = "v2"
      applied_at                    = "2020-01-01T00:00:00Z"
      last_checked_at               = "2999-01-01T00:00:00Z"
      pending_since                 = "2020-02-01T00:00:00Z"
      pending_security_groups_added = []
      pending_rules_added           = [for port in range(8001, 8026) : "i-0a1/in/tcp/${port}/10.0.0.0/8"]
      pending_rules_removed         = []
      pending_attachments_added     = []
      drift_evaluated               = true
      drift_observed_at             = "2020-01-02T00:00:00Z"
      drift_findings                = []
      notices                       = []
    }
  }

  expect_failures = [check.xshield_apply_overdue]

  assert {
    condition = (length(output.problems.apply_overdue) == 23 &&
    output.problems.apply_overdue[21] == "  add rule i-0a1/in/tcp/8020/10.0.0.0/8" && output.problems.apply_overdue[22] == "  and 5 more")
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "quiet_while_approved_policy_has_waited_less_than_the_limit" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published                 = true, state = "pending", expected_version = "v3", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since             = "2999-01-01T00:00:00Z", pending_security_groups_added = [], pending_rules_added = ["i-0a1/in/tcp/443/10.0.0.0/8"], pending_rules_removed = [],
      pending_attachments_added = [], drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = [], notices = []
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_published_policy_was_never_applied" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published                 = true, state = "unapplied", expected_version = "v1", applied_version = null, applied_at = null, last_checked_at = null,
      pending_since             = "2020-02-01T00:00:00Z", pending_security_groups_added = ["i-0a1"], pending_rules_added = ["i-0a1/in/tcp/443/10.0.0.0/8"], pending_rules_removed = [],
      pending_attachments_added = ["i-0a1/eni-0a1"], drift_evaluated = false, drift_observed_at = null, drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_never_applied]

  assert {
    condition     = keys(output.problems) == ["never_applied"] && output.problems.never_applied[0] == "Xshield policy for 123456789012/us-east-1 was published more than 24h ago and has never been applied:"
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_a_full_control_change_has_waited_too_long_for_the_owning_workspace" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "waiting", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "changeSetHeld", reason = "cs-old", asset_id = null, asset_name = null, group = "vpc-1/web", since = "2020-03-01T00:00:00Z", message = "the change waits for the workspace that owns web to apply" },
        { code = "changeSetHeld", reason = "cs-new", asset_id = null, asset_name = null, group = "vpc-1/admin", since = "2999-01-01T00:00:00Z", message = "the change waits for the workspace that owns admin to apply" },
        { code = "changeSetHeld", reason = "cs-undated", asset_id = null, asset_name = null, group = "vpc-1/db", since = null, message = "the change waits for the workspace that owns db to apply" },
      ]
    }
  }

  expect_failures = [check.xshield_owner_apply_overdue]

  assert {
    condition = output.problems == {
      owner_apply_overdue = [
        "A Full control change in 123456789012/us-east-1 has waited more than 24h for the workspace that owns a customer security group:",
        "  vpc-1/web: the change waits for the workspace that owns web to apply (change set cs-old, waiting since 2020-03-01T00:00:00Z)",
        "  vpc-1/db: the change waits for the workspace that owns db to apply (change set cs-undated, waiting since an unknown time)",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_the_enforcement_pipeline_has_stopped" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-06-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_pipeline_stopped]

  assert {
    condition     = keys(output.problems) == ["pipeline_stopped"] && startswith(output.problems.pipeline_stopped[1], "  last enforcement plan: 2020-06-01T00:00:00Z.")
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_drift_has_not_been_evaluated_since_an_apply_long_ago" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = null, drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_drift_not_evaluated]

  assert {
    condition     = keys(output.problems) == ["drift_not_evaluated"] && startswith(output.problems.drift_not_evaluated[1], "  applied 2020-01-01T00:00:00Z; last observation none.")
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "quiet_while_drift_is_not_yet_evaluated_after_a_fresh_apply" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2999-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = [], notices = []
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_on_a_port_whose_group_is_no_longer_narrowed" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "portNotNarrowed", reason = "cs-reverted", asset_id = "asset-web-1", asset_name = "i-0web1", group = "vpc-1/web", since = "2020-03-01T00:00:00Z", message = "inbound port TCP:443 is still deployed, but the change set that narrowed web for it was reverted" },
      ]
    }
  }

  expect_failures = [check.xshield_port_not_narrowed]

  assert {
    condition     = output.problems.port_not_narrowed[1] == "  i-0web1: inbound port TCP:443 is still deployed, but the change set that narrowed web for it was reverted (change set cs-reverted, reverted 2020-03-01T00:00:00Z)"
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "one_cause_shared_by_many_workloads_prints_one_line_that_names_them_all" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "waiting", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = concat(
        [for i in range(1, 11) : {
          code    = "changeSetHeld", reason = "cs-7a1", asset_id = format("asset-%02d", i), asset_name = format("app-%02d", i), group = "vpc-1/sg-web", since = "2020-03-01T00:00:00Z",
          message = "the change waits for the enforcement workspace's next apply to write the rules this workload keeps into vpc-1/sg-web"
        }],
        [{
          code    = "changeSetHeld", reason = "cs-7b2", asset_id = "asset-11", asset_name = "app-11", group = "vpc-1/sg-web", since = "2020-04-01T00:00:00Z",
          message = "the change waits for the enforcement workspace's next apply to write the rules this workload keeps into vpc-1/sg-web"
        }],
        [for held in [["app-01", "22", "sg-web"], ["app-02", "22", "sg-web"], ["app-03", "22", "sg-web"], ["app-01", "443", "sg-web"], ["app-02", "443", "sg-web"], ["app-03", "443", "sg-web"], ["app-03", "22", "sg-admin"]] : {
          code    = "portNotNarrowed", reason = "cs-7c3", asset_id = null, asset_name = held[0], group = "vpc-1/${held[2]}", since = "2020-05-01T00:00:00Z",
          message = "inbound port TCP:${held[1]} is still deployed, but the change set that narrowed vpc-1/${held[2]} for it was reverted: deploy the port again and approve the change it proposes"
        }],
        [{
          code    = "portNotNarrowed", reason = "cs-7d4", asset_id = null, asset_name = "app-04", group = "vpc-1/sg-web", since = "2020-06-01T00:00:00Z",
          message = "inbound port TCP:22 is still deployed, but the change set that narrowed vpc-1/sg-web for it was reverted: deploy the port again and approve the change it proposes"
        }],
      )
    }
  }

  expect_failures = [check.xshield_owner_apply_overdue, check.xshield_port_not_narrowed]

  assert {
    condition     = length(output.problems.owner_apply_overdue) == 3 && length(output.problems.port_not_narrowed) == 5
    error_message = "Each cause takes one line after the headline, but reported ${jsonencode(output.problems)}."
  }

  assert {
    condition = alltrue([
      for n in data.xshield_enforcement_status.this.notices : alltrue([
        for shown in [n.asset_name, n.group, n.reason, n.since, n.message] :
        strcontains(join("\n", output.problems[n.code == "changeSetHeld" ? "owner_apply_overdue" : "port_not_narrowed"]), shown)
      ])
    ])
    error_message = "A workload, group, change set, time or message of a notice is missing from ${jsonencode(output.problems)}."
  }

  assert {
    condition = length([
      for line in concat(output.problems.owner_apply_overdue, output.problems.port_not_narrowed) : line
      if strcontains(line, "cs-7a1") && strcontains(line, "cs-7b2") || strcontains(line, "cs-7c3") && strcontains(line, "cs-7d4")
    ]) == 0
    error_message = "Notices of different change sets share a line in ${jsonencode(output.problems)}."
  }

  assert {
    condition     = contains(output.problems.port_not_narrowed, "  app-01, app-02, app-03: inbound port TCP:22 is still deployed, but the change set that narrowed vpc-1/sg-web for it was reverted: deploy the port again and approve the change it proposes (change set cs-7c3, reverted 2020-05-01T00:00:00Z)")
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "withdrawn_groups_split_auto_scaling_groups_and_contained_workloads_are_silent_by_default" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "rds/old-db", since = null, message = "kept until discovery shows it detached" },
        { code = "asgPolicyDiffers", reason = null, asset_id = null, asset_name = null, group = "asg/web", since = null, message = "the instances of this Auto Scaling group do not have the same policy" },
        { code = "assetContained", reason = "CONTAINED", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "the asset is contained" },
      ]
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_on_withdrawn_groups_split_auto_scaling_groups_and_contained_workloads_when_asked" {
  command = plan

  variables {
    warn_on = ["group_withdrawing", "asg_policy_differs", "workload_contained"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = concat(
        [
          { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "rds/old-db", since = null, message = "policy no longer uses this security group: the workspace that owns rds/old-db detaches it at its next apply" },
          { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "lambda/old-fn", since = null, message = "policy no longer uses this security group: the workspace that owns lambda/old-fn detaches it at its next apply" },
          { code = "asgPolicyDiffers", reason = null, asset_id = null, asset_name = null, group = "asg/web", since = null, message = "the instances of this Auto Scaling group do not have the same policy, so each has a group of its own until they do" },
        ],
        [for i in range(1, 4) : {
          code    = "assetContained", reason = "CONTAINED", asset_id = format("asset-%02d", i), asset_name = format("app-%02d", i), group = null, since = null,
          message = "the asset is contained; its group stays as applied, off its interfaces, until the containment is reverted"
        }],
      )
    }
  }

  expect_failures = [check.xshield_group_withdrawing, check.xshield_asg_policy_differs, check.xshield_workload_contained]

  assert {
    condition     = length(output.problems.group_withdrawing) == 3 && length(output.problems.asg_policy_differs) == 2 && length(output.problems.workload_contained) == 2
    error_message = "Each cause takes one line after the headline, but reported ${jsonencode(output.problems)}."
  }

  assert {
    condition = alltrue([
      for n in data.xshield_enforcement_status.this.notices : alltrue([
        for shown in compact([n.asset_name, n.group, n.reason, n.message]) :
        strcontains(join("\n", output.problems[{ withdrawing = "group_withdrawing", asgPolicyDiffers = "asg_policy_differs", assetContained = "workload_contained" }[n.code]]), shown)
      ])
    ])
    error_message = "A workload, group, reason or message of a notice is missing from ${jsonencode(output.problems)}."
  }

  assert {
    condition     = output.problems.workload_contained[1] == "  app-01, app-02, app-03: the asset is contained; its group stays as applied, off its interfaces, until the containment is reverted (CONTAINED)"
    error_message = "Reported ${jsonencode(output.problems)}."
  }

  assert {
    condition     = output.problems.asg_policy_differs[1] == "  asg/web: the instances of this Auto Scaling group do not have the same policy, so each has a group of its own until they do"
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "a_contained_workload_named_in_fail_on_stops_the_plan" {
  command = plan

  variables {
    warn_on = []
    fail_on = ["workload_contained"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "assetContained", reason = "CONTAINED", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "the asset is contained" },
      ]
    }
  }

  expect_failures = [output.problems]
}

run "a_problem_left_out_of_warn_on_is_silent" {
  command = plan

  variables {
    warn_on = ["workload_not_enforced"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-06-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = null, notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline" },
      ]
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "a_problem_named_in_fail_on_stops_the_plan" {
  command = plan

  variables {
    fail_on = ["drift_high"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline" },
      ]
    }
  }

  expect_failures = [check.xshield_drift_high, output.problems]
}

run "fail_on_stops_nothing_while_its_problem_is_absent" {
  command = plan

  variables {
    fail_on = ["drift_high", "never_applied", "owner_apply_overdue"]
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "fail_on_alone_stops_the_plan_without_a_warning" {
  command = plan

  variables {
    warn_on = []
    fail_on = ["workload_not_enforced"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "groupRefused", reason = "RULE_BUDGET_EXCEEDED:inbound/ipv4=61", asset_id = null, asset_name = null, group = "i-0web1", since = null, message = "the group does not fit" },
      ]
    }
  }

  expect_failures = [output.problems]
}

run "an_unknown_problem_name_is_refused" {
  command = plan

  variables {
    fail_on = ["drift"]
  }

  expect_failures = [var.fail_on]
}

run "a_limit_that_is_no_duration_is_refused" {
  command = plan

  variables {
    max_run_gap = "3 days"
  }

  expect_failures = [var.max_run_gap]
}

run "notices_that_differ_in_group_message_reason_or_time_each_keep_a_line" {
  command = plan

  variables {
    warn_on = ["group_withdrawing", "workload_contained"]
  }

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = []
      notices = [
        { code = "assetContained", reason = "CONTAINED", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "the asset is contained" },
        { code = "assetContained", reason = "CONTAINED", asset_id = "asset-02", asset_name = "app-02", group = null, since = null, message = "the asset is contained, in other words" },
        { code = "assetContained", reason = "ISOLATED", asset_id = "asset-03", asset_name = "app-03", group = null, since = null, message = "the asset is contained" },
        { code = "assetContained", reason = "CONTAINED", asset_id = "asset-04", asset_name = "app-04", group = null, since = "2020-03-01T00:00:00Z", message = "the asset is contained" },
        { code = "withdrawing", reason = null, asset_id = "asset-05", asset_name = "db-01", group = "rds/old-db", since = null, message = "kept until it is detached" },
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "rds/older-db", since = null, message = "kept until it is detached" },
      ]
    }
  }

  expect_failures = [check.xshield_group_withdrawing, check.xshield_workload_contained]

  assert {
    condition     = length(output.problems.workload_contained) == 5 && length(output.problems.group_withdrawing) == 3
    error_message = "Four contained causes and two withdrawn groups each take a line after the headline, but reported ${jsonencode(output.problems)}."
  }

  assert {
    condition     = contains(output.problems.workload_contained, "  app-04: the asset is contained (CONTAINED) since 2020-03-01T00:00:00Z")
    error_message = "The time a notice carries is missing from ${jsonencode(output.problems.workload_contained)}."
  }

  assert {
    condition     = contains(output.problems.group_withdrawing, "  rds/old-db: kept until it is detached; workloads: db-01")
    error_message = "The workload a notice names beside its group is missing from ${jsonencode(output.problems.group_withdrawing)}."
  }
}

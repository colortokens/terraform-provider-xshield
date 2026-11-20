# terraform test, offline: each problem warns on what it should, stays quiet
# otherwise, says what a reader needs, and stops the plan only when named in
# fail_on. The Xshield provider is mocked. A time in 2020 is long ago; one in
# 2999 stands for "just now", since the checks compare with the plan's time.

mock_provider "xshield" {
  mock_data "xshield_aws_enforcement_status" {
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
      drift_observed_at             = "2999-01-01T00:00:00Z"
      drift_findings                = []
      notices                       = []
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
    target = data.xshield_aws_enforcement_status.this
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = false, state = "unpublished", expected_version = null, applied_version = null, applied_at = null, last_checked_at = null,
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = null, drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_unpublished]
}

run "warns_on_high_and_medium_severity_drift" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline", detected_at = null },
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0b2", resource_name = null, key = "i-0b2/in/tcp/443/10.0.0.0/8", detail = "the rule is gone", detected_at = null },
      ]
    }
  }

  expect_failures = [check.xshield_drift_high, check.xshield_drift_medium]

  assert {
    condition = output.problems == {
      drift_high = [
        "Xshield sees high-severity drift in 123456789012/us-east-1:",
        "  ruleUnmanaged sgr-0a1: tcp 22 from 0.0.0.0/0 was added outside the pipeline (fixed by: manual)",
      ]
      drift_medium = [
        "Xshield sees medium-severity drift in 123456789012/us-east-1:",
        "  ruleMissing sg-0b2: the rule is gone (fixed by: pipeline)",
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0b2", resource_name = null, key = "i-0b2/in/tcp/443/10.0.0.0/8", detail = "the rule is gone", detected_at = null },
      ]
    }
  }

  expect_failures = [check.xshield_drift_medium]
}

run "warns_on_a_refused_workload" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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

run "warns_by_default_on_workloads_awaiting_their_own_workspaces_attach" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "awaitingAttach", reason = null, asset_id = "asset-db-1", asset_name = "rds/orders-db", group = "rds/orders-db", since = null, message = "apply the workspace that defines rds/orders-db: the enforcement workspace created security group sg-0123456789abcdef0 for it" },
        { code = "awaitingAttach", reason = null, asset_id = "asset-fn-1", asset_name = null, group = "lambda/resize", since = null, message = "apply the workspace that defines this workload so it attaches security group sg-00000000000000001" },
      ]
    }
  }

  expect_failures = [check.xshield_awaiting_attach]

  assert {
    condition = output.problems == {
      awaiting_attach = [
        "Workloads in 123456789012/us-east-1 wait for their own workspace to attach Xshield's group, so their policy is not enforced:",
        "  rds/orders-db: apply the workspace that defines rds/orders-db: the enforcement workspace created security group sg-0123456789abcdef0 for it",
        "  asset-fn-1: apply the workspace that defines this workload so it attaches security group sg-00000000000000001",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "a_workload_awaiting_its_attach_named_in_fail_on_stops_the_plan" {
  command = plan

  variables {
    fail_on = ["awaiting_attach"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "awaitingAttach", reason = null, asset_id = "asset-db-1", asset_name = "rds/orders-db", group = "rds/orders-db", since = null, message = "apply the workspace that defines rds/orders-db" },
      ]
    }
  }

  expect_failures = [check.xshield_awaiting_attach, output.problems]
}

run "warns_once_per_cause_on_groups_whose_rule_count_is_a_guess_and_gives_the_connector_reason" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "prefixListSizeUnknown", reason = "UnauthorizedOperation", asset_id = null, asset_name = null, group = null, since = null, message = "the Xshield connector could not read the region's prefix lists, so Xshield's count of the rules is a guess until it can for each group whose rules name one: ct-policy-0a1b2c3d4e5f, ct-policy-5f4e3d2c1b0a. AWS counts a rule naming a prefix list as the list's maximum entries, and Xshield counts a list at the size it last read, or as one rule if it never read it: let the connector read them (ec2:DescribeManagedPrefixLists)" },
        { code = "prefixListSizeUnknown", reason = null, asset_id = null, asset_name = null, group = null, since = null, message = "Xshield has not sized prefix lists pl-0a1, pl-0b2, so Xshield's count of the rules is a guess for each group whose rules name one: ct-policy-0a1b2c3d4e5f, ct-policy-5f4e3d2c1b0a. AWS counts a rule naming a prefix list as the list's maximum entries, and Xshield counts a list it has not sized as one rule until the Xshield connector's discovery reads the region's prefix lists" },
        { code = "codeThisMonitorDoesNotKnow", reason = "ANY", asset_id = null, asset_name = null, group = "i-0db1", since = null, message = "a notice from a newer Xshield" },
      ]
    }
  }

  expect_failures = [check.xshield_prefix_list_size_unknown]

  assert {
    condition = output.problems == {
      prefix_list_size_unknown = [
        "Xshield's count of the rules of these groups in 123456789012/us-east-1 is a guess, so AWS may refuse their rules as over the quota of rules per security group:",
        "  the Xshield connector could not read the region's prefix lists, so Xshield's count of the rules is a guess until it can for each group whose rules name one: ct-policy-0a1b2c3d4e5f, ct-policy-5f4e3d2c1b0a. AWS counts a rule naming a prefix list as the list's maximum entries, and Xshield counts a list at the size it last read, or as one rule if it never read it: let the connector read them (ec2:DescribeManagedPrefixLists) (UnauthorizedOperation)",
        "  Xshield has not sized prefix lists pl-0a1, pl-0b2, so Xshield's count of the rules is a guess for each group whose rules name one: ct-policy-0a1b2c3d4e5f, ct-policy-5f4e3d2c1b0a. AWS counts a rule naming a prefix list as the list's maximum entries, and Xshield counts a list it has not sized as one rule until the Xshield connector's discovery reads the region's prefix lists",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "a_notice_code_the_monitor_does_not_know_is_not_reported" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "codeThisMonitorDoesNotKnow", reason = "ANY", asset_id = null, asset_name = null, group = "i-0db1", since = null, message = "a notice from a newer Xshield" },
      ]
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_approved_policy_has_waited_too_long_and_counts_everything_waiting" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published                 = true, state = "pending", expected_version = "v3", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since             = "2020-02-01T00:00:00Z", pending_security_groups_added = ["i-0new"], pending_rules_added = [], pending_rules_removed = ["i-0a1/in/tcp/22/10.0.0.0/8"],
      pending_attachments_added = ["i-0new/eni-0new"], drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = [], notices = []
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

run "an_overdue_version_of_changes_the_status_does_not_count_is_not_reported_as_nothing_waiting" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published                 = true, state = "pending", expected_version = "v3", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since             = "2020-02-01T00:00:00Z", pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [],
      pending_attachments_added = [], drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_apply_overdue]

  assert {
    condition = (length(output.problems.apply_overdue) == 2 && !strcontains(output.problems.apply_overdue[1], "0 group(s)") &&
    strcontains(output.problems.apply_overdue[1], "network ACL entries"))
    error_message = "A waiting version that changes only what the status does not count, such as network ACL entries, must not read as zero changes, but reported ${jsonencode(output.problems)}."
  }
}

run "lists_twenty_waiting_changes_and_counts_the_rest" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
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
      drift_observed_at             = "2999-01-01T00:00:00Z"
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published                 = true, state = "pending", expected_version = "v3", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since             = "2999-01-01T00:00:00Z", pending_security_groups_added = [], pending_rules_added = ["i-0a1/in/tcp/443/10.0.0.0/8"], pending_rules_removed = [],
      pending_attachments_added = [], drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = [], notices = []
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
    target = data.xshield_aws_enforcement_status.this
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "waiting", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-06-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_pipeline_stopped]

  assert {
    condition     = keys(output.problems) == ["pipeline_stopped"] && startswith(output.problems.pipeline_stopped[1], "  last enforcement plan: 2020-06-01T00:00:00Z.")
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "quiet_about_the_pipeline_once_the_account_is_handed_back_to_the_connector" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "handedOver", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-06-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = [], notices = []
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_when_drift_has_not_been_evaluated_since_an_apply_long_ago" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
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

run "warns_when_the_latest_observation_is_older_than_max_unobserved_age" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = [], notices = []
    }
  }

  expect_failures = [check.xshield_drift_not_evaluated]

  assert {
    condition = output.problems == {
      drift_not_evaluated = [
        "Xshield has not evaluated drift in 123456789012/us-east-1 for more than 30m:",
        "  applied 2020-01-01T00:00:00Z; last observation 2020-01-02T00:00:00Z. No drift finding here means nobody looked, not that nothing drifted: check that the cloud connector is running and can reach the account.",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "quiet_on_an_old_observation_once_handed_over" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "handedOver", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z", drift_findings = [], notices = []
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "The cloud connector looks for drift once the account is handed over, but reported ${jsonencode(output.problems)}."
  }
}

run "warns_on_drift_still_there_after_max_apply_age" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0b2", resource_name = null, key = "i-0b2/in/tcp/443/10.0.0.0/8", detail = "the rule is gone", detected_at = "2020-01-03T00:00:00Z" },
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0c3", resource_name = null, key = "i-0c3/in/tcp/443/10.0.0.0/8", detail = "the rule is gone", detected_at = "2999-01-01T00:00:00Z" },
        { kind = "memberWithdrawing", severity = "medium", restoration = "pipeline", resource = "sg-0d4", resource_name = null, key = null, detail = "the group is being withdrawn", detected_at = null },
      ]
    }
  }

  expect_failures = [check.xshield_drift_medium, check.xshield_drift_unrestored]

  assert {
    condition = output.problems.drift_unrestored == [
      "Drift Xshield recorded in 123456789012/us-east-1 more than 24h ago is still there:",
      "  medium ruleMissing sg-0b2: the rule is gone (detected 2020-01-03T00:00:00Z; fixed by: pipeline)",
    ]
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "quiet_while_drift_is_not_yet_evaluated_after_a_fresh_apply" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "waiting", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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
      for n in data.xshield_aws_enforcement_status.this.notices : alltrue([
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

run "split_auto_scaling_groups_and_contained_workloads_are_silent_by_default" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "asgPolicyDiffers", reason = null, asset_id = null, asset_name = null, group = "asg/web", since = null, message = "the instances of this Auto Scaling group do not have the same policy" },
        { code = "assetContained", reason = "CONTAINED", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "the asset is contained" },
        { code = "assetPolicyInTest", reason = "inbound", asset_id = "asset-02", asset_name = "app-02", group = null, since = null, message = "the asset's inbound policy is in test, which adds no rule on AWS" },
      ]
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_by_default_on_groups_still_held_after_policy_stopped_using_them" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v3", applied_version = "v3", applied_at = "2999-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "lambda/resize", since = null, message = "policy no longer uses this security group, but AWS cannot delete it while it is held by network interface eni-0fn (AWS Lambda VPC ENI-resize): AWS keeps a function's interface while a version of the function lists the group, so delete version 7 of resize once no alias uses it; then AWS releases the interface on its own, some time later; it is kept, with its rules, until discovery shows nothing holds it" },
      ]
    }
  }

  expect_failures = [check.xshield_group_withdrawing]

  assert {
    condition = output.problems.group_withdrawing == [
      "Security groups policy no longer uses in 123456789012/us-east-1 are still held, so the enforcement workspace cannot delete them yet:",
      "  lambda/resize: policy no longer uses this security group, but AWS cannot delete it while it is held by network interface eni-0fn (AWS Lambda VPC ENI-resize): AWS keeps a function's interface while a version of the function lists the group, so delete version 7 of resize once no alias uses it; then AWS releases the interface on its own, some time later; it is kept, with its rules, until discovery shows nothing holds it",
    ]
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "a_group_still_held_is_silent_when_left_out_of_warn_on" {
  command = plan

  variables {
    warn_on = ["drift_high"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v3", applied_version = "v3", applied_at = "2999-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "rds/old-db", since = null, message = "kept until discovery shows it detached" },
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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
      for n in data.xshield_aws_enforcement_status.this.notices : alltrue([
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

run "warns_on_asset_policies_in_test_when_asked_with_one_line_for_each_direction" {
  command = plan

  variables {
    warn_on = ["asset_policy_in_test"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "assetPolicyInTest", reason = "inbound", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "the asset's inbound policy is in test, which adds no rule on AWS" },
        { code = "assetPolicyInTest", reason = "inbound", asset_id = "asset-02", asset_name = "app-02", group = null, since = null, message = "the asset's inbound policy is in test, which adds no rule on AWS" },
        { code = "assetPolicyInTest", reason = "outbound", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "the asset's outbound policy is in test, which adds no rule on AWS" },
      ]
    }
  }

  expect_failures = [check.xshield_asset_policy_in_test]

  assert {
    condition = output.problems.asset_policy_in_test == [
      "Workloads in 123456789012/us-east-1 have an asset policy in test, which writes no rule on AWS:",
      "  app-01, app-02: the asset's inbound policy is in test, which adds no rule on AWS (inbound)",
      "  app-01: the asset's outbound policy is in test, which adds no rule on AWS (outbound)",
    ]
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_by_default_on_unacknowledged_carriers_and_block_templates_aws_does_not_enforce" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "carriersNotAcknowledged", reason = null, asset_id = null, asset_name = null, group = "vpc-1/sg-web", since = null, message = "lb-1 carry sg-web and were not shown when the change was approved: Xshield keeps the rules the change moves out of sg-web until they are acknowledged" },
        { code = "blockRuleNotEnforced", reason = "Block telnet", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "this block template blocks inbound tcp port 23, which AWS does not block for this workload" },
        { code = "blockRuleNotEnforced", reason = "Block telnet", asset_id = "asset-02", asset_name = "app-02", group = null, since = null, message = "this block template blocks inbound tcp port 23, which AWS does not block for this workload" },
        { code = "blockRuleNotEnforced", reason = "Block telnet", asset_id = "asset-03", asset_name = "app-03", group = null, since = null, message = "this block template blocks inbound tcp port 23, outbound udp ports 137-139, which AWS does not block for this workload" },
        { code = "revertEnded", reason = "cs-9", asset_id = null, asset_name = null, group = "vpc-1/sg-db", since = null, message = "the revert of change set cs-9 ended without sg-db shown holding its moved rules again" },
      ]
    }
  }

  expect_failures = [check.xshield_carriers_not_acknowledged, check.xshield_block_rule_not_enforced]

  assert {
    condition = output.problems.carriers_not_acknowledged == [
      "Full control changes in 123456789012/us-east-1 move rules out of security groups that something carries which no approval showed:",
      "  vpc-1/sg-web: lb-1 carry sg-web and were not shown when the change was approved: Xshield keeps the rules the change moves out of sg-web until they are acknowledged",
    ]
    error_message = "Reported ${jsonencode(output.problems)}."
  }

  assert {
    condition = output.problems.block_rule_not_enforced == [
      "Workloads in 123456789012/us-east-1 have block templates, which AWS does not enforce. For the malicious IP block template, see \"Turning on the malicious IP block\" in the Xshield pipeline delivery reference:",
      "  app-01, app-02: this block template blocks inbound tcp port 23, which AWS does not block for this workload (Block telnet)",
      "  app-03: this block template blocks inbound tcp port 23, outbound udp ports 137-139, which AWS does not block for this workload (Block telnet)",
    ]
    error_message = "Reported ${jsonencode(output.problems)}."
  }

  assert {
    condition     = !contains(keys(output.problems), "revert_ended")
    error_message = "An ended revert is not warned by default, but reported ${jsonencode(output.problems)}."
  }
}

run "a_malicious_ip_block_template_aws_does_not_enforce_points_at_turning_it_on" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "blockRuleNotEnforced", reason = "Malicious Deny", asset_id = "asset-01", asset_name = "web-1", group = null, since = null, message = "the malicious IP block template is assigned to this workload, and AWS does not block its addresses" },
      ]
    }
  }

  expect_failures = [check.xshield_block_rule_not_enforced]

  assert {
    condition     = strcontains(output.problems.block_rule_not_enforced[0], "\"Turning on the malicious IP block\" in the Xshield pipeline delivery reference")
    error_message = "A malicious IP block template AWS does not enforce must point at turning the block on, but reported ${jsonencode(output.problems)}."
  }
}

run "warns_on_an_ended_revert_when_asked" {
  command = plan

  variables {
    warn_on = ["revert_ended"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "revertEnded", reason = "cs-9", asset_id = null, asset_name = null, group = "vpc-1/sg-db", since = null, message = "the revert of change set cs-9 ended without sg-db shown holding its moved rules again" },
      ]
    }
  }

  expect_failures = [check.xshield_revert_ended]

  assert {
    condition = output.problems == {
      revert_ended = [
        "Full control reverts in 123456789012/us-east-1 ended without the customer security group shown holding its moved rules again:",
        "  vpc-1/sg-db: the revert of change set cs-9 ended without sg-db shown holding its moved rules again",
      ]
    }
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "warns_by_default_on_malicious_addresses_a_network_acl_does_not_block" {
  command = plan

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "networkAclEntryRefused", reason = "ACL_FULL:in", asset_id = null, asset_name = null, group = "acl-0a1b", since = null, message = "this network ACL has no inbound place left for these addresses of the malicious IP block template, so they are not blocked for the workloads behind it: 203.0.113.7/32" },
        { code = "networkAclNotObserved", reason = "NOT_READ", asset_id = null, asset_name = null, group = "acl-0c2d", since = null, message = "the cloud connector has not read this network ACL, so Xshield adds no entry to it and these addresses of the malicious IP block template are not blocked for the workloads behind it: 198.51.100.9/32" },
        { code = "networkAclEntryShadowed", reason = null, asset_id = null, asset_name = null, group = "acl-0a1b", since = null, message = "an allow numbered before the deny of 198.51.100.10/32 lets the traffic it denies through" },
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "rds/old-db", since = null, message = "kept until discovery shows it detached" },
      ]
    }
  }

  expect_failures = [check.xshield_network_acl_block_not_enforced, check.xshield_group_withdrawing]

  assert {
    condition = output.problems.network_acl_block_not_enforced == [
      "Addresses of the malicious IP block template are not blocked on these network ACLs in 123456789012/us-east-1:",
      "  acl-0a1b: this network ACL has no inbound place left for these addresses of the malicious IP block template, so they are not blocked for the workloads behind it: 203.0.113.7/32 (ACL_FULL:in)",
      "  acl-0c2d: the cloud connector has not read this network ACL, so Xshield adds no entry to it and these addresses of the malicious IP block template are not blocked for the workloads behind it: 198.51.100.9/32 (NOT_READ)",
      "  acl-0a1b: an allow numbered before the deny of 198.51.100.10/32 lets the traffic it denies through",
    ]
    error_message = "Reported ${jsonencode(output.problems)}."
  }
}

run "a_network_acl_block_named_in_fail_on_stops_the_plan" {
  command = plan

  variables {
    warn_on = []
    fail_on = ["network_acl_block_not_enforced"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "networkAclEntryRefused", reason = "NO_FREE_SLOT:out", asset_id = null, asset_name = null, group = "acl-0a1b", since = null, message = "no outbound rule number is free for these addresses on this network ACL in front of the allows that cover them, nor among the even numbers 50 to 98" },
      ]
    }
  }

  expect_failures = [output.problems]
}

run "a_block_template_named_in_fail_on_stops_the_plan" {
  command = plan

  variables {
    warn_on = []
    fail_on = ["block_rule_not_enforced"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "blockRuleNotEnforced", reason = "Block telnet", asset_id = "asset-01", asset_name = "app-01", group = null, since = null, message = "this block template blocks inbound tcp port 23, which AWS does not block for this workload" },
      ]
    }
  }

  expect_failures = [output.problems]
}

run "a_contained_workload_named_in_fail_on_stops_the_plan" {
  command = plan

  variables {
    warn_on = []
    fail_on = ["workload_contained"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-06-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = false, drift_observed_at = null, notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline", detected_at = null },
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline", detected_at = null },
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "converged", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
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

# What keeps two notices on separate lines: for a held change its subject, change set and time; for a port its
# group and change set; for a deliberate state its kind. A notice that names no workload adds none to a line.
run "held_changes_ports_and_states_that_differ_in_subject_change_set_time_or_kind_each_keep_a_line" {
  command = plan

  variables {
    warn_on = ["owner_apply_overdue", "port_not_narrowed", "group_withdrawing", "asg_policy_differs"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "waiting", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2999-01-01T00:00:00Z",
      pending_since   = null, pending_security_groups_added = [], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2999-01-01T00:00:00Z", drift_findings = []
      notices = [
        { code = "changeSetHeld", reason = "cs-1", asset_id = "asset-01", asset_name = "app-01", group = null, since = "2020-02-01T00:00:00Z", message = "waits for its interface" },
        { code = "changeSetHeld", reason = "cs-1", asset_id = "asset-02", asset_name = "app-02", group = null, since = "2020-02-01T00:00:00Z", message = "waits for its interface" },
        { code = "changeSetHeld", reason = "cs-1", asset_id = "asset-03", asset_name = "app-03", group = "web", since = "2020-02-01T00:00:00Z", message = "waits for the owner" },
        { code = "changeSetHeld", reason = "cs-1", asset_id = "asset-04", asset_name = "app-04", group = "web", since = "2020-03-01T00:00:00Z", message = "waits for the owner" },
        { code = "portNotNarrowed", reason = "cs-9", asset_id = "asset-05", asset_name = "app-05", group = "web", since = "2020-02-01T00:00:00Z", message = "TCP 443 is not narrowed" },
        { code = "portNotNarrowed", reason = "cs-9", asset_id = null, asset_name = null, group = "web", since = "2020-02-01T00:00:00Z", message = "TCP 443 is not narrowed" },
        { code = "portNotNarrowed", reason = "cs-9", asset_id = "asset-06", asset_name = "app-06", group = "app", since = "2020-02-01T00:00:00Z", message = "TCP 443 is not narrowed" },
        { code = "portNotNarrowed", reason = "cs-8", asset_id = "asset-07", asset_name = "app-07", group = "web", since = "2020-02-01T00:00:00Z", message = "TCP 443 is not narrowed" },
        { code = "withdrawing", reason = null, asset_id = null, asset_name = null, group = "asg/orders", since = null, message = "is in a state Xshield chose" },
        { code = "asgPolicyDiffers", reason = null, asset_id = null, asset_name = null, group = "asg/orders", since = null, message = "is in a state Xshield chose" },
      ]
    }
  }

  expect_failures = [check.xshield_owner_apply_overdue, check.xshield_port_not_narrowed, check.xshield_group_withdrawing, check.xshield_asg_policy_differs]

  assert {
    condition = alltrue([
      length(output.problems.owner_apply_overdue) == 5,
      contains(output.problems.owner_apply_overdue, "  app-01: waits for its interface (change set cs-1, waiting since 2020-02-01T00:00:00Z)"),
      contains(output.problems.owner_apply_overdue, "  app-02: waits for its interface (change set cs-1, waiting since 2020-02-01T00:00:00Z)"),
      contains(output.problems.owner_apply_overdue, "  web: waits for the owner (change set cs-1, waiting since 2020-02-01T00:00:00Z; workloads: app-03)"),
      contains(output.problems.owner_apply_overdue, "  web: waits for the owner (change set cs-1, waiting since 2020-03-01T00:00:00Z; workloads: app-04)"),
    ])
    error_message = "A held change with no group is its workload's own line, and one group's change keeps a line for each time it has waited since, but reported ${jsonencode(output.problems.owner_apply_overdue)}."
  }

  assert {
    condition = alltrue([
      length(output.problems.port_not_narrowed) == 4,
      contains(output.problems.port_not_narrowed, "  app-05: TCP 443 is not narrowed (change set cs-9, reverted 2020-02-01T00:00:00Z)"),
      contains(output.problems.port_not_narrowed, "  app-06: TCP 443 is not narrowed (change set cs-9, reverted 2020-02-01T00:00:00Z)"),
      contains(output.problems.port_not_narrowed, "  app-07: TCP 443 is not narrowed (change set cs-8, reverted 2020-02-01T00:00:00Z)"),
    ])
    error_message = "A port keeps a line for each group and each change set, and a notice that names no workload adds none, but reported ${jsonencode(output.problems.port_not_narrowed)}."
  }

  assert {
    condition     = length(output.problems.group_withdrawing) == 2 && length(output.problems.asg_policy_differs) == 2
    error_message = "A withdrawn group and a split Auto Scaling group with the same words are two problems, but reported ${jsonencode(output.problems)}."
  }
}

run "quiet_about_every_notice_and_finding_frozen_at_the_hand_over" {
  command = plan

  variables {
    warn_on = [
      "drift_high", "drift_medium", "drift_unrestored", "workload_not_enforced", "awaiting_attach", "prefix_list_size_unknown", "apply_overdue", "never_applied",
      "owner_apply_overdue", "pipeline_stopped", "drift_not_evaluated", "port_not_narrowed", "unpublished",
      "group_withdrawing", "asg_policy_differs", "workload_contained", "asset_policy_in_test", "carriers_not_acknowledged",
      "revert_ended", "block_rule_not_enforced", "network_acl_block_not_enforced",
    ]
    fail_on = ["awaiting_attach", "group_withdrawing", "drift_high"]
  }

  override_data {
    target = data.xshield_aws_enforcement_status.this
    values = {
      published       = true, state = "handedOver", expected_version = "v2", applied_version = "v2", applied_at = "2020-01-01T00:00:00Z", last_checked_at = "2020-01-01T00:00:00Z",
      pending_since   = "2020-01-01T00:00:00Z", pending_security_groups_added = ["web-1"], pending_rules_added = [], pending_rules_removed = [], pending_attachments_added = [],
      drift_evaluated = true, drift_observed_at = "2020-01-02T00:00:00Z"
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", resource_name = null, key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline", detected_at = "2020-01-01T00:00:00Z" },
        { kind = "ruleMissing", severity = "medium", restoration = "pipeline", resource = "sg-0b2", resource_name = null, key = "i-0b2/in/tcp/443/10.0.0.0/8", detail = "the rule is gone", detected_at = null },
      ]
      notices = [
        for code in [
          "assetRefused", "groupRefused", "awaitingAttach", "prefixListSizeUnknown", "changeSetHeld", "portNotNarrowed", "withdrawing", "asgPolicyDiffers",
          "assetContained", "assetPolicyInTest", "carriersNotAcknowledged", "revertEnded", "blockRuleNotEnforced", "networkAclEntryRefused",
          "networkAclNotObserved", "networkAclEntryShadowed",
        ] : { code = code, reason = null, asset_id = "asset-db-1", asset_name = "rds/db-1", group = "rds/db-1", since = "2020-01-01T00:00:00Z", message = "frozen at the hand-over" }
      ]
    }
  }

  assert {
    condition     = length(output.problems) == 0
    error_message = "The status keeps what it showed at the hand-over and the cloud connector delivers now, so nothing here can be cleared, but the monitor reported ${jsonencode(output.problems)}."
  }
}

# terraform test, offline: shows the checks alert on what they should and stay
# quiet otherwise, with the Xshield provider mocked.

mock_provider "xshield" {
  mock_data "xshield_enforcement_status" {
    defaults = {
      published      = true
      state          = "converged"
      pending_since  = null
      drift_findings = []
      notices = [
        { code = "withdrawing", reason = null, asset_id = null, group = "rds/old-db", message = "kept until discovery shows it detached" },
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
}

run "quiet_when_nothing_is_published" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      published        = false
      state            = "unpublished"
      expected_version = null
      applied_version  = null
      pending_since    = null
      notices          = []
      drift_findings   = []
    }
  }
}

run "alerts_on_high_severity_drift" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      state   = "converged"
      notices = []
      drift_findings = [
        { kind = "ruleUnmanaged", severity = "high", restoration = "manual", resource = "sgr-0a1", key = "i-0a1", detail = "tcp 22 from 0.0.0.0/0 was added outside the pipeline" },
      ]
    }
  }

  expect_failures = [check.xshield_enforcement]
}

run "alerts_on_a_refused_workload" {
  command = plan

  override_data {
    target = data.xshield_enforcement_status.this
    values = {
      state          = "converged"
      drift_findings = []
      notices = [
        { code = "assetRefused", reason = "NO_FREE_SLOT", asset_id = "asset-web-1", group = null, message = "the connector would refuse this workload's policy" },
      ]
    }
  }

  expect_failures = [check.xshield_enforcement]
}

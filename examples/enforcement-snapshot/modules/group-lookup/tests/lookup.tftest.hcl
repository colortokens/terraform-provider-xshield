# terraform test, offline: the AWS provider is mocked, returning the directory
# entry the enforcement module writes for rds/orders-db.

mock_provider "aws" {
  mock_data "aws_ssm_parameters_by_path" {
    defaults = {
      names  = ["/colortokens/v1/rds/orders-db/security-groups"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"]}"]
    }
  }
}

run "returns_listed_group" {
  variables {
    handle = "rds/orders-db"
  }

  assert {
    condition     = output.security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "the lookup returns the directory entry's group IDs"
  }
  assert {
    condition     = data.aws_ssm_parameters_by_path.entry.path == "/colortokens/v1/rds/orders-db" && data.aws_ssm_parameters_by_path.entry.recursive == null
    error_message = "the lookup reads only the handle's own path"
  }
}

run "returns_nothing_without_rules" {
  variables {
    handle = "rds/orders-db"
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/rds/orders-db/security-groups"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[]}"]
    }
  }

  assert {
    condition     = output.security_group_ids == []
    error_message = "an entry listing no group attaches nothing"
  }
}

# Before Xshield publishes anything for the account, or lists this resource,
# there is no parameter: the resource's own plan must go ahead unchanged.
run "returns_nothing_without_an_entry" {
  variables {
    handle = "rds/orders-db"
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = { names = [], values = [] }
  }

  assert {
    condition     = output.security_group_ids == []
    error_message = "a resource Xshield lists no entry for attaches nothing, and its plan does not fail"
  }
}

run "ignores_other_parameters_under_the_handle" {
  variables {
    handle = "rds/orders-db"
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/rds/orders-db/notes"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[\"sg-0bad\"]}"]
    }
  }

  assert {
    condition     = output.security_group_ids == []
    error_message = "only the security-groups parameter is read"
  }
}

run "rejects_handle_without_kind" {
  command = plan

  variables {
    handle = "orders-db"
  }

  expect_failures = [var.handle]
}

run "refuses_entry_for_another_handle" {
  command = plan

  variables {
    handle = "rds/billing-db"
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/rds/billing-db/security-groups"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"]}"]
    }
  }

  expect_failures = [output.security_group_ids]
}

run "fails_without_an_entry_when_one_is_required" {
  command = plan

  variables {
    handle        = "rds/orders-dbb"
    require_entry = true
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = { names = [], values = [] }
  }

  expect_failures = [output.security_group_ids]
}

run "returns_listed_group_when_an_entry_is_required" {
  variables {
    handle        = "rds/orders-db"
    require_entry = true
  }

  assert {
    condition     = output.security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "a required entry that exists is returned as usual"
  }
}

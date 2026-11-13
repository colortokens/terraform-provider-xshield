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

  expect_failures = [data.aws_ssm_parameters_by_path.entry]
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

# Asked to, the plan warns about a handle with no entry yet and goes ahead.
run "warns_without_an_entry" {
  command = plan

  variables {
    handle             = "rds/orders-dbb"
    warn_when_unlisted = true
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = { names = [], values = [] }
  }

  expect_failures = [check.directory_entry]
}

# RDS stores identifiers in lowercase, and Xshield's handle comes from the ARN.
run "lowercases_an_rds_handle" {
  variables {
    handle = "rds/Orders-DB"
  }

  assert {
    condition     = data.aws_ssm_parameters_by_path.entry.path == "/colortokens/v1/rds/orders-db" && output.security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "an RDS handle is read in lowercase"
  }
}

run "keeps_the_case_of_other_handles" {
  variables {
    handle = "lambda/Orders-API"
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/lambda/Orders-API/security-groups"]
      values = ["{\"handle\":\"lambda/Orders-API\",\"security_group_ids\":[\"sg-0aa\"]}"]
    }
  }

  assert {
    condition     = data.aws_ssm_parameters_by_path.entry.path == "/colortokens/v1/lambda/Orders-API" && output.security_group_ids == ["sg-0aa"]
    error_message = "a Lambda function name keeps its case"
  }
}

# A developer adding a group of their own learns at plan, not from AWS at apply,
# that it no longer fits beside Xshield's.
run "own_groups_that_do_not_fit_fail_the_plan" {
  command = plan

  variables {
    handle                 = "rds/orders-db"
    own_security_group_ids = ["sg-01", "sg-02", "sg-03", "sg-04", "sg-05"]
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/rds/orders-db/security-groups"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"],\"slot_limit\":5}"]
    }
  }

  expect_failures = [output.security_group_ids]
}

run "own_groups_that_fit_pass_and_room_is_reported" {
  command = plan

  variables {
    handle                 = "rds/orders-db"
    own_security_group_ids = ["sg-01", "sg-02", "sg-03", "sg-04"]
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/rds/orders-db/security-groups"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"],\"slot_limit\":5}"]
    }
  }

  assert {
    condition     = output.own_security_groups_allowed == 4
    error_message = "a limit of five less Xshield's one group leaves four"
  }
}

# Before Xshield has discovered the limit, nothing is checked and the room is unknown.
run "without_a_limit_nothing_is_checked" {
  command = plan

  variables {
    handle                 = "rds/orders-db"
    own_security_group_ids = ["sg-01", "sg-02", "sg-03", "sg-04", "sg-05", "sg-06"]
  }

  assert {
    condition     = output.own_security_groups_allowed == null && output.security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "an entry without a limit returns its groups and leaves the room unknown"
  }
}

# An Auto Scaling group's launch template reads its group by the group's own name.
run "reads_an_auto_scaling_group_by_its_name" {
  variables {
    handle = "asg/Orders-Web"
  }

  override_data {
    target = data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/asg/Orders-Web/security-groups"]
      values = ["{\"handle\":\"asg/Orders-Web\",\"security_group_ids\":[\"sg-0asg\"]}"]
    }
  }

  assert {
    condition     = data.aws_ssm_parameters_by_path.entry.path == "/colortokens/v1/asg/Orders-Web" && output.security_group_ids == ["sg-0asg"]
    error_message = "an Auto Scaling group is read under asg/ and its name, in the name's own case"
  }
}

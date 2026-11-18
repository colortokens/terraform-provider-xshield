# terraform test, offline: the AWS provider is mocked, returning the directory
# entry the enforcement workspace writes for lambda/resize. The runs share one
# state, as the workspace does: the function takes the group, then gives it up.

mock_provider "aws" {
  mock_data "aws_ssm_parameters_by_path" {
    defaults = {
      names  = ["/colortokens/v1/lambda/resize/security-groups"]
      values = ["{\"handle\":\"lambda/resize\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"],\"security_group_ids_by_vpc\":{\"vpc-0a1b2c3d4e5f60718\":[\"sg-0f1e2d3c4b5a69788\"]},\"slot_limit\":5}"]
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id = "sg-0a1b2c3d4e5f60718"
    }
  }
}

variables {
  vpc_id      = "vpc-0a1b2c3d4e5f60718"
  subnet_ids  = ["subnet-0a1b2c3d4e5f60718"]
  role_arn    = "arn:aws:iam::123456789012:role/resize-function"
  code_bucket = "resize-artifacts"
  code_key    = "resize.zip"
}

run "function_carries_the_xshield_group_beside_its_own" {
  assert {
    condition     = aws_lambda_function.resize.vpc_config[0].security_group_ids == toset(["sg-0a1b2c3d4e5f60718", "sg-0f1e2d3c4b5a69788"])
    error_message = "the function carries its own group and the group of its directory entry"
  }
  assert {
    condition     = output.xshield_security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "the output names the group Xshield gave the function"
  }
  assert {
    condition     = output.own_security_groups_allowed == 4
    error_message = "a limit of five less Xshield's one group leaves four"
  }
}

# After a rollback the enforcement workspace's apply leaves the entry listing no
# group, and keeps the group until discovery shows it detached.
run "a_rolled_back_function_gives_up_the_xshield_group_and_keeps_its_own" {
  command = plan

  override_data {
    target = module.resize_xshield.data.aws_ssm_parameters_by_path.entry
    values = {
      names  = ["/colortokens/v1/lambda/resize/security-groups"]
      values = ["{\"handle\":\"lambda/resize\",\"security_group_ids\":[],\"security_group_ids_by_vpc\":{},\"slot_limit\":5}"]
    }
  }

  assert {
    condition     = aws_lambda_function.resize.vpc_config[0].security_group_ids == toset(["sg-0a1b2c3d4e5f60718"])
    error_message = "the function still carries Xshield's group after the entry stopped listing it"
  }
  assert {
    condition     = output.xshield_security_group_ids == []
    error_message = "the output is empty once the entry lists no group"
  }
}

# Once the enforcement workspace has deleted the group, it deletes the entry too.
run "a_function_xshield_lists_no_entry_for_carries_only_its_own_group" {
  command = plan

  override_data {
    target = module.resize_xshield.data.aws_ssm_parameters_by_path.entry
    values = { names = [], values = [] }
  }

  assert {
    condition     = aws_lambda_function.resize.vpc_config[0].security_group_ids == toset(["sg-0a1b2c3d4e5f60718"])
    error_message = "a function Xshield lists no entry for carries only its own group"
  }
  assert {
    condition     = output.xshield_security_group_ids == []
    error_message = "the output is empty while Xshield lists no entry"
  }
}

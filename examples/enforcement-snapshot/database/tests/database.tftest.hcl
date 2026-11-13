# terraform test, offline: the AWS provider is mocked, returning the directory
# entry the enforcement workspace writes for rds/orders-db.

mock_provider "aws" {
  mock_data "aws_ssm_parameters_by_path" {
    defaults = {
      names  = ["/colortokens/v1/rds/orders-db/security-groups"]
      values = ["{\"handle\":\"rds/orders-db\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"],\"slot_limit\":5}"]
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id = "sg-0a1b2c3d4e5f60718"
    }
  }
}

variables {
  vpc_id = "vpc-0a1b2c3d4e5f60718"
}

run "database_carries_the_xshield_group_beside_its_own" {
  assert {
    condition     = aws_db_instance.orders.vpc_security_group_ids == toset(["sg-0a1b2c3d4e5f60718", "sg-0f1e2d3c4b5a69788"])
    error_message = "the database carries its own group and the group of its directory entry"
  }
  assert {
    condition     = output.xshield_security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "the output names the group Xshield gave the database"
  }
  assert {
    condition     = output.own_security_groups_allowed == 4
    error_message = "a limit of five less Xshield's one group leaves four"
  }
}

# Before Xshield lists the database, and after it withdraws the group, the
# database carries its own group alone.
run "database_carries_only_its_own_group_without_an_entry" {
  override_data {
    target = module.orders_db_xshield.data.aws_ssm_parameters_by_path.entry
    values = { names = [], values = [] }
  }

  assert {
    condition     = aws_db_instance.orders.vpc_security_group_ids == toset(["sg-0a1b2c3d4e5f60718"])
    error_message = "a database Xshield lists no entry for carries only its own group"
  }
  assert {
    condition     = output.xshield_security_group_ids == []
    error_message = "the output is empty while Xshield lists no entry"
  }
}

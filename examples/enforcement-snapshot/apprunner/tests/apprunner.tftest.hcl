# terraform test, offline: the AWS provider is mocked, returning the directory
# entry the enforcement workspace writes for apprunner/orders-web.

mock_provider "aws" {
  mock_data "aws_ssm_parameters_by_path" {
    defaults = {
      names  = ["/colortokens/v1/apprunner/orders-web/security-groups"]
      values = ["{\"handle\":\"apprunner/orders-web\",\"security_group_ids\":[\"sg-0f1e2d3c4b5a69788\"],\"slot_limit\":5}"]
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id = "sg-0a1b2c3d4e5f60718"
    }
  }

  # The service validates its connector's ARN, which a mock would otherwise fill with a random string.
  mock_resource "aws_apprunner_vpc_connector" {
    defaults = {
      arn = "arn:aws:apprunner:us-east-1:123456789012:vpcconnector/orders-web/1/0123456789abcdef0123456789abcdef"
    }
  }
}

variables {
  vpc_id     = "vpc-0a1b2c3d4e5f60718"
  subnet_ids = ["subnet-0a1b2c3d4e5f60718"]
}

run "connector_carries_the_xshield_group_beside_the_services_own" {
  assert {
    condition     = aws_apprunner_vpc_connector.orders_web.security_groups == toset(["sg-0a1b2c3d4e5f60718", "sg-0f1e2d3c4b5a69788"])
    error_message = "the connector carries the service's own group and the group of its directory entry"
  }
  assert {
    condition     = aws_apprunner_service.orders_web.network_configuration[0].egress_configuration[0].vpc_connector_arn == aws_apprunner_vpc_connector.orders_web.arn
    error_message = "the service sends its traffic through that connector"
  }
  assert {
    condition     = output.xshield_security_group_ids == ["sg-0f1e2d3c4b5a69788"]
    error_message = "the output names the group Xshield gave the service"
  }
  assert {
    condition     = output.own_security_groups_allowed == 4
    error_message = "a limit of five less Xshield's one group leaves four"
  }
}

# Before Xshield lists the service, and after it withdraws the group, the
# connector carries the service's own group alone.
run "connector_carries_only_the_services_own_group_without_an_entry" {
  override_data {
    target = module.orders_web_xshield.data.aws_ssm_parameters_by_path.entry
    values = { names = [], values = [] }
  }

  assert {
    condition     = aws_apprunner_vpc_connector.orders_web.security_groups == toset(["sg-0a1b2c3d4e5f60718"])
    error_message = "a service Xshield lists no entry for carries only its own group"
  }
  assert {
    condition     = output.xshield_security_group_ids == []
    error_message = "the output is empty while Xshield lists no entry"
  }
}

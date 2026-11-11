# The workspace of the team that owns the orders-web App Runner service. It
# declares nothing of Xshield's. The service's Xshield group reaches it in four
# steps:
#
#   1. Xshield renders the group and every rule in it from the service's policy.
#   2. The enforcement workspace (../enforcement) creates the group and its
#      rules, and writes the group's ID to the SSM parameter
#      /colortokens/v1/apprunner/orders-web/security-groups.
#   3. module.orders_web_xshield reads that parameter by the handle
#      apprunner/orders-web.
#   4. The service's VPC connector carries the group beside the service's own.
#
# App Runner takes security groups only on the VPC connector the service sends
# its traffic through, and every service on a connector gets the connector's
# groups. So the service gets a connector of its own. The groups govern only
# the service's outbound traffic into the VPC.
#
# This workspace reads only SSM, and needs no Xshield credentials.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

locals {
  service_name = "orders-web"
}

# Xshield's group. The handle is the service's kind and its name.
# own_security_group_ids fails the plan, rather than the apply, when the
# service's own groups and Xshield's are more than AWS allows on the connector.
module "orders_web_xshield" {
  source = "../modules/aws-group-lookup"

  handle                 = "apprunner/${local.service_name}"
  own_security_group_ids = [aws_security_group.orders_web.id]
}

# The team's own group and rule. Xshield creates neither and changes neither.
# Under Full control, declare the group's rules through
# ../modules/aws-security-group-rules instead: step 4 of the README.
resource "aws_security_group" "orders_web" {
  name        = "orders-web"
  description = "Rules the orders team declares for orders-web"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "telemetry" {
  security_group_id = aws_security_group.orders_web.id
  description       = "Traces to the telemetry collector"
  ip_protocol       = "tcp"
  from_port         = 4317
  to_port           = 4317
  cidr_ipv4         = "10.20.9.9/32"
}

locals {
  orders_web_groups = concat([aws_security_group.orders_web.id], module.orders_web_xshield.security_group_ids)
}

# A connector's groups cannot change, so a new group list means a new
# connector; its name follows the list, and the service moves to the new
# connector before the old one is deleted.
resource "aws_apprunner_vpc_connector" "orders_web" {
  vpc_connector_name = "orders-web-${substr(sha1(join(",", sort(local.orders_web_groups))), 0, 8)}"
  subnets            = var.subnet_ids
  security_groups    = local.orders_web_groups

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_apprunner_service" "orders_web" {
  service_name = local.service_name

  source_configuration {
    auto_deployments_enabled = false
    image_repository {
      image_identifier      = var.image
      image_repository_type = "ECR_PUBLIC"
      image_configuration {
        port = "8000"
      }
    }
  }

  network_configuration {
    egress_configuration {
      egress_type       = "VPC"
      vpc_connector_arn = aws_apprunner_vpc_connector.orders_web.arn
    }
  }
}

variable "vpc_id" {
  description = "VPC the service reaches through its connector."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets of that VPC for the connector."
  type        = list(string)
}

variable "image" {
  description = "Public ECR image the service runs."
  type        = string
  default     = "public.ecr.aws/aws-containers/hello-app-runner:latest"
}

output "xshield_security_group_ids" {
  description = "The security groups Xshield gave the service, which the enforcement workspace creates with their rules. Empty while Xshield lists no entry for the service. A plan shows a group arriving or leaving under Changes to Outputs."
  value       = module.orders_web_xshield.security_group_ids
}

output "own_security_groups_allowed" {
  description = "How many security groups of its own the service's connector can carry beside Xshield's. Null until Xshield has discovered the limit."
  value       = module.orders_web_xshield.own_security_groups_allowed
}

# The orders team's own workspace: its App Runner service, the service's own
# security group and rule, and the VPC connector the service sends its traffic
# through. It stands in for a workspace you already have. Nothing in this file
# is Xshield's: the team's group and rule stay as declared here. Two things
# changed for Xshield, marked below. What the team added is in xshield.tf.

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
  # Changed for Xshield: the group it gave the service goes beside the team's own.
  orders_web_groups = concat([aws_security_group.orders_web.id], module.orders_web_xshield.security_group_ids)
}

# Changed for Xshield: the service has a connector of its own, because every
# service on a connector gets the connector's groups. A connector's groups
# cannot change, so a new group list means a new connector; its name follows
# the list, and the service moves to the new connector before the old one is
# deleted.
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

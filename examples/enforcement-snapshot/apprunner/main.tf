# A workspace that owns an App Runner service. App Runner takes security groups
# only on the VPC connector the service sends its traffic through, and every
# service on a connector gets the connector's groups. So the service gets a
# connector of its own, holding its own group and the one Xshield gave it. The
# groups govern only the service's outbound traffic into the VPC.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

module "orders_web_xshield" {
  source = "../modules/group-lookup"
  handle = "apprunner/orders-web"
}

resource "aws_security_group" "orders_web" {
  name   = "orders-web"
  vpc_id = var.vpc_id
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
  service_name = "orders-web"

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

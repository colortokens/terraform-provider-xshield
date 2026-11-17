# The resize team's own workspace: its Lambda function, which runs in a VPC, the
# function's own security group and that group's rule. It stands in for a
# workspace you already have. Nothing in this file is Xshield's: the team's
# group and rule stay as declared here. One line changed for Xshield, marked
# below. What the team added is in xshield.tf.

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
  function_name = "resize"
}

resource "aws_security_group" "resize" {
  name        = "resize"
  description = "Rules the resize team declares for its function"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "image_store" {
  security_group_id = aws_security_group.resize.id
  description       = "Images from the internal image store"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "10.20.7.0/24"
}

resource "aws_lambda_function" "resize" {
  function_name = local.function_name
  role          = var.role_arn
  runtime       = "python3.12"
  handler       = "app.handler"
  s3_bucket     = var.code_bucket
  s3_key        = var.code_key

  vpc_config {
    subnet_ids = var.subnet_ids
    # Changed for Xshield: the group it gave the function goes beside the team's own.
    security_group_ids = concat([aws_security_group.resize.id], module.resize_xshield.security_group_ids)
  }
}

variable "vpc_id" {
  description = "VPC the function runs in."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets of that VPC the function's network interfaces go in."
  type        = list(string)
}

variable "role_arn" {
  description = "The function's execution role. A function in a VPC needs the permissions of the AWSLambdaVPCAccessExecutionRole managed policy."
  type        = string
}

variable "code_bucket" {
  description = "S3 bucket holding the function's deployment package."
  type        = string
}

variable "code_key" {
  description = "S3 key of the deployment package."
  type        = string
}

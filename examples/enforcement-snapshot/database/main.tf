# The orders team's own workspace: its database, the database's own security
# group and that group's rule. It stands in for a workspace you already have.
# Nothing in this file is Xshield's: the team's group and rule stay as declared
# here. One line changed for Xshield, marked below. What the team added is in
# xshield.tf.

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
  identifier = "orders-db"
}

resource "aws_security_group" "orders_db" {
  name        = "orders-db"
  description = "Rules the orders team declares for orders-db"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "schema_migrations" {
  security_group_id = aws_security_group.orders_db.id
  description       = "Schema migrations from the deploy runner"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = "10.20.9.5/32"
}

resource "aws_db_instance" "orders" {
  identifier                  = local.identifier
  engine                      = "postgres"
  instance_class              = "db.t4g.medium"
  allocated_storage           = 20
  username                    = "orders"
  manage_master_user_password = true
  skip_final_snapshot         = true

  # Changed for Xshield: the group it gave the database goes beside the team's own.
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}

variable "vpc_id" {
  description = "VPC the database runs in."
  type        = string
}

# A workspace that owns a database. The enforcement workspace cannot attach a
# group to an RDS instance it does not manage, so this workspace adds the group
# Xshield gave the database to the database's own list. It reads only SSM.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

module "orders_db_xshield" {
  source = "../modules/group-lookup"
  handle = "rds/orders-db"
}

resource "aws_security_group" "orders_db" {
  name   = "orders-db"
  vpc_id = var.vpc_id
}

resource "aws_db_instance" "orders" {
  identifier                  = "orders-db"
  engine                      = "postgres"
  instance_class              = "db.t4g.medium"
  allocated_storage           = 20
  username                    = "orders"
  manage_master_user_password = true
  skip_final_snapshot         = true

  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}

variable "vpc_id" {
  description = "VPC the database runs in."
  type        = string
}

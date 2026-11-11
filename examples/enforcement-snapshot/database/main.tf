# The workspace of the team that owns the orders database. It declares nothing
# of Xshield's. The database's Xshield group reaches it in four steps:
#
#   1. Xshield renders the group and every rule in it from the database's policy.
#   2. The enforcement workspace (../enforcement) creates the group and its
#      rules, and writes the group's ID to the SSM parameter
#      /colortokens/v1/rds/orders-db/security-groups.
#   3. module.orders_db_xshield reads that parameter by the handle rds/orders-db.
#   4. aws_db_instance.orders carries the group beside its own, because the
#      enforcement workspace cannot attach a group to an RDS instance it does
#      not manage.
#
# So this workspace reads only SSM, and needs no Xshield credentials.

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

# Xshield's group. The handle is the database's kind and its identifier.
# own_security_group_ids fails the plan, rather than the apply, when the
# database's own groups and Xshield's are more than AWS allows on it.
module "orders_db_xshield" {
  source = "../modules/aws-group-lookup"

  handle                 = "rds/${local.identifier}"
  own_security_group_ids = [aws_security_group.orders_db.id]
}

# The team's own group and rule. Xshield creates neither and changes neither.
# Under Full control, declare the group's rules through
# ../modules/aws-security-group-rules instead: step 4 of the README.
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

  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}

variable "vpc_id" {
  description = "VPC the database runs in."
  type        = string
}

output "xshield_security_group_ids" {
  description = "The security groups Xshield gave the database, which the enforcement workspace creates with their rules. Empty while Xshield lists no entry for the database. A plan shows a group arriving or leaving under Changes to Outputs."
  value       = module.orders_db_xshield.security_group_ids
}

output "own_security_groups_allowed" {
  description = "How many security groups of its own the database can carry beside Xshield's. Null until Xshield has discovered the limit."
  value       = module.orders_db_xshield.own_security_groups_allowed
}

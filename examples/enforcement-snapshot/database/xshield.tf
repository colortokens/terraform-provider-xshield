# Everything the orders team adds for Xshield. It declares no group and no rule
# of Xshield's. The database's Xshield group reaches it in four steps:
#
#   1. Xshield renders the group and every rule in it from the database's policy.
#   2. The enforcement workspace (../enforcement) creates the group and its
#      rules, and writes the group's ID to the SSM parameter
#      /colortokens/v1/rds/orders-db/security-groups.
#   3. The module below reads that parameter by the handle rds/orders-db: the
#      database's kind and the identifier the team gave it.
#   4. aws_db_instance.orders in main.tf carries the group beside its own,
#      because the enforcement workspace cannot attach a group to an RDS
#      instance it does not manage.
#
# The module reads only SSM, so this workspace needs no Xshield provider and no
# Xshield credentials. A change to the group's rules never shows in its plan.

# own_security_group_ids fails the plan, rather than the apply, when the
# database's own groups and Xshield's are more than AWS allows on it.
module "orders_db_xshield" {
  source = "../modules/aws-group-lookup"

  handle                 = "rds/${local.identifier}"
  own_security_group_ids = [aws_security_group.orders_db.id]
}

output "xshield_security_group_ids" {
  description = "The security groups Xshield gave the database, which the enforcement workspace creates with their rules. Empty while Xshield lists no entry for the database. A plan shows a group arriving or leaving under Changes to Outputs."
  value       = module.orders_db_xshield.security_group_ids
}

output "own_security_groups_allowed" {
  description = "How many security groups of its own the database can carry beside Xshield's. Null until Xshield has discovered the limit."
  value       = module.orders_db_xshield.own_security_groups_allowed
}

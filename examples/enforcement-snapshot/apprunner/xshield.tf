# Everything the orders team adds for Xshield. It declares no group and no rule
# of Xshield's. The service's Xshield group reaches it in four steps:
#
#   1. Xshield renders the group and every rule in it from the service's policy.
#   2. The enforcement workspace (../enforcement) creates the group and its
#      rules, and writes the group's ID to the SSM parameter
#      /colortokens/v1/apprunner/orders-web/security-groups.
#   3. The module below reads that parameter by the handle
#      apprunner/orders-web: the service's kind and the name the team gave it.
#   4. The service's VPC connector in main.tf carries the group beside the
#      service's own. App Runner takes security groups only on the connector,
#      and they govern only the service's outbound traffic into the VPC.
#
# The module reads only SSM, so this workspace needs no Xshield provider and no
# Xshield credentials. A change to the group's rules never shows in its plan.

# own_security_group_ids fails the plan, rather than the apply, when the
# service's own groups and Xshield's are more than AWS allows on the connector.
module "orders_web_xshield" {
  source = "../modules/aws-group-lookup"

  handle                 = "apprunner/${local.service_name}"
  own_security_group_ids = [aws_security_group.orders_web.id]
}

output "xshield_security_group_ids" {
  description = "The security groups Xshield gave the service, which the enforcement workspace creates with their rules. Empty while Xshield lists no entry for the service. A plan shows a group arriving or leaving under Changes to Outputs."
  value       = module.orders_web_xshield.security_group_ids
}

output "own_security_groups_allowed" {
  description = "How many security groups of its own the service's connector can carry beside Xshield's. Null until Xshield has discovered the limit."
  value       = module.orders_web_xshield.own_security_groups_allowed
}

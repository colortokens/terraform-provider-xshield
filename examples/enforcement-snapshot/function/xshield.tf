# Everything the resize team adds for Xshield. It declares no group and no rule
# of Xshield's. The function's Xshield group reaches it in four steps:
#
#   1. Xshield renders the group and every rule in it from the function's policy.
#   2. The enforcement workspace (../enforcement) creates the group and its
#      rules, and writes the group's ID to the SSM parameter
#      /colortokens/v1/lambda/resize/security-groups.
#   3. The module below reads that parameter by the handle lambda/resize: the
#      function's kind and the name the team gave it.
#   4. aws_lambda_function.resize in main.tf carries the group beside its own,
#      because the enforcement workspace cannot attach a group to a function it
#      does not manage.
#
# When policy stops using the group, as after a rollback, it leaves the same
# way. The enforcement workspace's apply empties the parameter but keeps the
# group and its rules, so the function loses no access; this workspace's next
# apply takes the group out of the function's configuration; and once the cloud
# connector shows nothing holding the group, the enforcement workspace's next
# apply deletes it. AWS keeps a function's network interface for some time after
# its configuration changes, and a published version keeps the configuration it
# was published with, so with publish = true delete the versions that list the
# group once no alias uses them. The withdrawing notice of the
# xshield_enforcement_status data source names what still holds the group.
#
# The module reads only SSM, so this workspace needs no Xshield provider and no
# Xshield credentials. A change to the group's rules never shows in its plan.

# own_security_group_ids fails the plan, rather than the apply, when the
# function's own groups and Xshield's are more than AWS allows on it.
module "resize_xshield" {
  source = "../modules/aws-group-lookup"

  handle                 = "lambda/${local.function_name}"
  own_security_group_ids = [aws_security_group.resize.id]
}

output "xshield_security_group_ids" {
  description = "The security groups Xshield gave the function, which the enforcement workspace creates with their rules. Empty while Xshield lists no entry for the function, and once policy stops using its group. A plan shows a group arriving or leaving under Changes to Outputs."
  value       = module.resize_xshield.security_group_ids
}

output "own_security_groups_allowed" {
  description = "How many security groups of its own the function can carry beside Xshield's. Null until Xshield has discovered the limit."
  value       = module.resize_xshield.own_security_groups_allowed
}

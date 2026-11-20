# Hands an account to connector delivery without removing what the cloud connector now keeps: replace
# the module "xshield_enforcement" block with this one, remove the outputs that read the module (summary and
# xshield_review in enforcement/main.tf), and apply once. The groups, rules, attachments, network ACL
# entries and directory parameters stay in the account; Terraform only stops managing them. Delete this
# file afterwards, finish the workspaces that look their groups up as below, and then remove the directory
# parameters.
#
# The cloud connector sets the groups of each database, function and service itself and leaves only its own
# groups on it, so a workspace that still applies its lookup puts the team's groups back and takes off any group
# the connector has added since. Before the switch to connector delivery, each such workspace adds the attribute
# that lists the resource's groups to ignore_changes and applies, as the Xshield pipeline delivery reference says. If
# that was not done before the switch, stop the runs of those workspaces now, do it in each before any of them runs
# again and before you apply this file, and give each workload in Xshield's policy any access only its team's own
# groups allowed. A resource declared inside a module takes no lifecycle block from the module call: point the
# call at a copy of the module in which the resource ignores the attribute; the resource keeps its address.
#
# The network ACL entries stay in place, and Xshield no longer tracks them; a cloud connector that blocks
# addresses on network ACLs itself may change or delete an entry at a rule number it uses. Before you apply,
# list them from the state, which also holds any an apply created whose receipt Xshield refused, and the old
# number of a deny that apply was moving, kept as a deposed object that terraform state show leaves out:
#   terraform show -json | jq -r '.values.root_module | .. | objects | select(.type? == "aws_network_acl_rule") | .values | "\(.network_acl_id) \(.rule_number) \(.egress) \([.cidr_block, .ipv6_cidr_block] | map(select(. != null and . != "")) | first)"'
# Each line gives an entry's network_acl_id, rule_number, egress and address. Once an address is no
# longer to be blocked, as when it leaves the malicious IP block template or the template is unassigned, check
# that the entry at its number still denies that address on all protocols, as the number may hold another entry
# by then, and only then delete it:
#   aws ec2 describe-network-acls --network-acl-ids <network_acl_id> --query 'NetworkAcls[].Entries[?RuleNumber==`<rule_number>` && Egress==`<egress>`]'
#   aws ec2 delete-network-acl-entry --network-acl-id <network_acl_id> --rule-number <rule_number> --ingress
# with --egress instead of --ingress for an entry whose egress is true.
#
# The directory parameters stay because the workspaces that own a database, function or service look their groups
# up through them. List them before you apply, as the state stops holding them:
#   terraform show -json | jq -r '.values.root_module | .. | objects | select(.mode? == "managed" and .type? == "aws_ssm_parameter") | .values.name'
# Each name is /colortokens/v1/<handle>/security-groups, for the handle a group lookup names.
#
# Once this file is applied, remove from each workspace with a lookup the lookup module and the outputs that read
# it, give the resource only its own groups where it took the lookup's (in the database, function and apprunner
# examples, delete xshield.tf and make the line marked "Changed for Xshield" list the team's group alone), and
# apply: with the attribute ignored, the plan shows no change. Removing the lookup without ignore_changes takes the
# group off the resource, as does deleting its parameter while a lookup still reads it. The attributes are:
#   aws_db_instance, aws_rds_cluster                        vpc_security_group_ids
#   aws_launch_template                                     vpc_security_group_ids, or network_interfaces[0].security_groups
#   aws_lambda_function                                     vpc_config[0].security_group_ids
#   aws_kinesisanalyticsv2_application                      application_configuration[0].vpc_configuration[0].security_group_ids
#   aws_apprunner_service                                   network_configuration[0].egress_configuration[0].vpc_connector_arn
#   aws_apprunner_vpc_connector                             vpc_connector_name, security_groups
# The last two are for an App Runner service, which the connector moves to a VPC connector that carries only its
# groups. Once no workspace uses a lookup with its handle, delete the parameter:
#   aws ssm delete-parameter --name <name>
removed {
  from = module.xshield_enforcement

  lifecycle {
    destroy = false
  }
}

# Fails a plan that adds a rule giving a group's workloads traffic an approved Xshield change takes from some of them.
package terraform.policies.xshield_reopened_access

import data.terraform.lib.xshield

deny contains message if {
	some source in xshield.rules_sources
	group := source.values.security_group_id
	is_string(group)
	some reopen in source.values.reopens
	[direction, key] := xshield.split_rule(reopen.rule)
	declared := source.values[direction][key]
	want := xshield.traffic(declared)
	some change in xshield.rule_changes
	change.type == sprintf("aws_vpc_security_group_%s_rule", [direction])
	xshield.adds(change, group, want)
	message := sprintf(
		"%s adds %s to security group %s (%s). Every workload in the group gets this rule's traffic, and Xshield change set %s takes some of it from some of the group's workloads. Give a workload this access through its Xshield policy instead, which gives it to that workload alone.",
		[change.address, xshield.describe(direction, declared), source.values.group_name, group, reopen.change_set],
	)
}

# Fails a plan that deletes or changes a rule an approved Xshield change still needs in the group.
package terraform.policies.xshield_removed_early

import data.terraform.lib.xshield

deny contains message if {
	some source in xshield.rules_sources
	group := source.values.security_group_id
	is_string(group)
	some pending in source.values.undeclared_pending
	want := xshield.traffic(pending)
	some change in xshield.rule_changes
	change.type == sprintf("aws_vpc_security_group_%s_rule", [pending.direction])
	xshield.removes(change, group, want)
	message := sprintf(
		"%s takes %s out of security group %s (%s) before Xshield change set %s is ready for it. Until every workload that keeps this traffic carries its cohort group, those workloads lose it. Declare the rule again through xshield_aws_security_group_rules; Xshield leaves it out itself once it is safe.",
		[change.address, xshield.describe(pending.direction, pending), source.values.group_name, group, pending.change_set],
	)
}

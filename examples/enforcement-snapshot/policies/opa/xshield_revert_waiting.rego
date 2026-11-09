# Reports the rules a revert of an Xshield change waits for this workspace to declare again.
package terraform.policies.xshield_revert_waiting

import data.terraform.lib.xshield

warn contains message if {
	some source in xshield.rules_sources
	some restore in source.values.undeclared_restores
	message := sprintf(
		"Xshield is reverting change set %s on security group %s (%s) and waits for this workspace to declare %s again. Until it does, Xshield keeps the access every workload in the group has now. Declare the rule through xshield_security_group_rules to end the wait.",
		[restore.change_set, source.values.group_name, source.values.security_group_id, xshield.describe(restore.direction, restore)],
	)
}

package terraform.policies.xshield_test

import data.terraform.policies.xshield_removed_early
import data.terraform.policies.xshield_reopened_access
import data.terraform.policies.xshield_revert_waiting

ssh := {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "10.0.0.0/8", "cidr_ipv6": null, "prefix_list_id": null, "referenced_security_group_id": null}

http := object.union(ssh, {"from_port": 80, "to_port": 80})

source(facts) := {
	"address": "module.web.data.xshield_security_group_rules.this",
	"mode": "data",
	"type": "xshield_security_group_rules",
	"values": object.union(
		{
			"group_name": "web",
			"security_group_id": "sg-web",
			"ingress": {"ssh": object.union(ssh, {"description": null}), "path/ssh": ssh},
			"egress": {"ssh_out": ssh},
			"reopens": [],
			"undeclared_restores": [],
			"undeclared_pending": [],
		},
		facts,
	),
}

plan_with(changes, facts) := {
	"prior_state": {"values": {"root_module": {"child_modules": [{"resources": [source(facts)]}]}}},
	"resource_changes": changes,
}

plan(changes, reopens, restores) := plan_with(changes, {"reopens": reopens, "undeclared_restores": restores})

rule_change(address, type, actions, before, after) := {"address": address, "type": type, "change": {"actions": actions, "before": before, "after": after}}

ingress(address, actions, before, after) := rule_change(address, "aws_vpc_security_group_ingress_rule", actions, before, after)

in_group(rule, group) := object.union(rule, {"security_group_id": group})

reopened_ssh := [{"rule": "ingress/ssh", "change_set": "cs-1"}]

test_a_created_rule_that_reopens_access_fails if {
	count(xshield_reopened_access.deny) == 1 with input as plan([ingress("a", ["create"], null, in_group(ssh, "sg-web"))], reopened_ssh, [])
}

test_hcp_terraform_input_shape if {
	count(xshield_reopened_access.deny) == 1 with input as {"plan": plan([ingress("a", ["create"], null, in_group(ssh, "sg-web"))], reopened_ssh, [])}
}

test_a_rule_the_group_already_held_under_another_key_passes if {
	count(xshield_reopened_access.deny) == 0 with input as plan(
		[
			ingress("new", ["create"], null, in_group(ssh, "sg-web")),
			ingress("old", ["delete"], in_group(ssh, "sg-web"), null),
		],
		reopened_ssh, [],
	)
}

test_a_replacement_with_the_same_traffic_passes if {
	count(xshield_reopened_access.deny) == 0 with input as plan([ingress("a", ["delete", "create"], in_group(ssh, "sg-web"), in_group(ssh, "sg-web"))], reopened_ssh, [])
}

test_a_rule_deleted_from_another_group_does_not_excuse_it if {
	count(xshield_reopened_access.deny) == 1 with input as plan(
		[
			ingress("new", ["create"], null, in_group(ssh, "sg-web")),
			ingress("old", ["delete"], in_group(ssh, "sg-other"), null),
		],
		reopened_ssh, [],
	)
}

test_an_update_that_changes_the_traffic_fails if {
	count(xshield_reopened_access.deny) == 1 with input as plan([ingress("a", ["update"], in_group(http, "sg-web"), in_group(ssh, "sg-web"))], reopened_ssh, [])
}

test_an_update_of_the_description_alone_passes if {
	before := object.union(in_group(ssh, "sg-web"), {"description": "old"})
	count(xshield_reopened_access.deny) == 0 with input as plan([ingress("a", ["update"], before, in_group(ssh, "sg-web"))], reopened_ssh, [])
}

test_another_groups_rule_passes if {
	count(xshield_reopened_access.deny) == 0 with input as plan([ingress("a", ["create"], null, in_group(ssh, "sg-other"))], reopened_ssh, [])
}

test_a_group_with_nothing_reopened_passes if {
	count(xshield_reopened_access.deny) == 0 with input as plan([ingress("a", ["create"], null, in_group(ssh, "sg-web"))], [], [])
}

test_a_key_holding_a_slash if {
	count(xshield_reopened_access.deny) == 1 with input as plan([ingress("a", ["create"], null, in_group(ssh, "sg-web"))], [{"rule": "ingress/path/ssh", "change_set": "cs-1"}], [])
}

test_egress if {
	out := rule_change("a", "aws_vpc_security_group_egress_rule", ["create"], null, in_group(ssh, "sg-web"))
	count(xshield_reopened_access.deny) == 1 with input as plan([out], [{"rule": "egress/ssh_out", "change_set": "cs-1"}], [])
	count(xshield_reopened_access.deny) == 0 with input as plan([out], reopened_ssh, [])
}

test_protocol_number_and_name_are_the_same_traffic if {
	count(xshield_reopened_access.deny) == 1 with input as plan([ingress("a", ["create"], null, in_group(object.union(ssh, {"ip_protocol": "6"}), "sg-web"))], reopened_ssh, [])
}

test_a_revert_waiting_on_an_undeclared_rule_warns_on_any_plan if {
	restore := object.union(ssh, {"direction": "ingress", "change_set": "cs-0"})
	warnings := xshield_revert_waiting.warn with input as plan([], [], [restore])
	warnings == {"Xshield is reverting change set cs-0 on security group web (sg-web) and waits for this workspace to declare tcp 22 from 10.0.0.0/8 again. Until it does, Xshield keeps the access every workload in the group has now. Declare the rule through xshield_security_group_rules to end the wait."}
}

test_nothing_to_restore_no_warning if {
	count(xshield_revert_waiting.warn) == 0 with input as plan([], [], [])
}

pending_ssh := {"undeclared_pending": [object.union(ssh, {"direction": "ingress", "change_set": "cs-2"})]}

removed_early(changes) := denied if {
	denied := xshield_removed_early.deny with input as plan_with(changes, pending_ssh)
}

test_a_deleted_rule_a_change_still_needs_fails if {
	removed_early([ingress("module.web.x[\"ssh\"]", ["delete"], in_group(ssh, "sg-web"), null)]) == {"module.web.x[\"ssh\"] takes tcp 22 from 10.0.0.0/8 out of security group web (sg-web) before Xshield change set cs-2 is ready for it. Until every workload that keeps this traffic carries its cohort group, those workloads lose it. Declare the rule again through xshield_security_group_rules; Xshield leaves it out itself once it is safe."}
}

test_an_update_that_takes_the_traffic_out_fails if {
	count(removed_early([ingress("a", ["update"], in_group(ssh, "sg-web"), in_group(http, "sg-web"))])) == 1
}

test_an_update_of_the_description_alone_keeps_the_rule if {
	after := object.union(in_group(ssh, "sg-web"), {"description": "new"})
	count(removed_early([ingress("a", ["update"], in_group(ssh, "sg-web"), after)])) == 0
}

test_a_rule_moved_to_another_key_is_kept if {
	count(removed_early([
		ingress("old", ["delete"], in_group(ssh, "sg-web"), null),
		ingress("new", ["create"], null, in_group(ssh, "sg-web")),
	])) == 0
}

test_a_replacement_with_the_same_traffic_is_kept if {
	count(removed_early([ingress("a", ["delete", "create"], in_group(ssh, "sg-web"), in_group(ssh, "sg-web"))])) == 0
}

test_a_rule_created_in_another_group_does_not_excuse_it if {
	count(removed_early([
		ingress("old", ["delete"], in_group(ssh, "sg-web"), null),
		ingress("new", ["create"], null, in_group(ssh, "sg-other")),
	])) == 1
}

test_a_deletion_from_another_group_passes if {
	count(removed_early([ingress("a", ["delete"], in_group(ssh, "sg-other"), null)])) == 0
}

test_a_deleted_rule_no_change_needs_passes if {
	count(removed_early([ingress("a", ["delete"], in_group(http, "sg-web"), null)])) == 0
	count(xshield_removed_early.deny) == 0 with input as plan([ingress("a", ["delete"], in_group(ssh, "sg-web"), null)], [], [])
}

test_a_pending_egress_rule_is_not_an_ingress_rule if {
	count(removed_early([rule_change("a", "aws_vpc_security_group_egress_rule", ["delete"], in_group(ssh, "sg-web"), null)])) == 0
}

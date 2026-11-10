# HCP Terraform passes the plan as input.plan; `opa eval` and conftest take the plan JSON as the input itself.
package terraform.lib.xshield

plan := object.get(input, "plan", input)

rule_types := {"aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"}

rules_sources contains source if {
	walk(plan.prior_state, [path, source])
	path[count(path) - 2] == "resources"
	source.mode == "data"
	source.type == "xshield_aws_security_group_rules"
}

rule_changes contains change if {
	some change in plan.resource_changes
	change.type in rule_types
}

protocol_names := {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "all": "-1"}

canonical_protocol(protocol) := object.get(protocol_names, lower(protocol), lower(protocol))

traffic(rule) := object.union(peer(rule), {"protocol": "-1"}) if canonical_protocol(rule.ip_protocol) == "-1"

traffic(rule) := object.union(peer(rule), {
	"protocol": canonical_protocol(rule.ip_protocol),
	"from_port": object.get(rule, "from_port", null),
	"to_port": object.get(rule, "to_port", null),
}) if canonical_protocol(rule.ip_protocol) != "-1"

peer(rule) := {name: object.get(rule, name, null) | some name in ["cidr_ipv4", "cidr_ipv6", "prefix_list_id", "referenced_security_group_id"]}

split_rule(rule) := [substring(rule, 0, i), substring(rule, i + 1, -1)] if i := indexof(rule, "/")

# A rule the group had under another key or address is kept, not added.
adds(change, group, want) if {
	"create" in change.change.actions
	change.change.after.security_group_id == group
	traffic(change.change.after) == want
	not had_before(change.type, group, want)
}

adds(change, group, want) if {
	change.change.actions == ["update"]
	change.change.after.security_group_id == group
	traffic(change.change.after) == want
	not had(change.change.before, group, want)
}

had_before(type, group, want) if {
	some other in rule_changes
	other.type == type
	"delete" in other.change.actions
	had(other.change.before, group, want)
}

had(rule, group, want) if {
	rule.security_group_id == group
	traffic(rule) == want
}

# A rule moved to another key or address in the same plan is kept, not removed.
removes(change, group, want) if {
	"delete" in change.change.actions
	had(change.change.before, group, want)
	not has_after(change.type, group, want)
}

removes(change, group, want) if {
	change.change.actions == ["update"]
	had(change.change.before, group, want)
	not had(change.change.after, group, want)
}

has_after(type, group, want) if {
	some other in rule_changes
	other.type == type
	"create" in other.change.actions
	had(other.change.after, group, want)
}

describe(direction, rule) := sprintf("%s %s %s", [ports_of(traffic(rule)), peer_word[direction], peer_of(rule)])

peer_word := {"ingress": "from", "egress": "to"}

ports_of(t) := "all traffic" if t.protocol == "-1"

ports_of(t) := t.protocol if {
	t.protocol != "-1"
	t.from_port in {null, -1}
}

ports_of(t) := sprintf("%s %v", [t.protocol, t.from_port]) if {
	not t.from_port in {null, -1}
	t.from_port == t.to_port
}

ports_of(t) := sprintf("%s %v-%v", [t.protocol, t.from_port, t.to_port]) if {
	not t.from_port in {null, -1}
	t.from_port != t.to_port
}

peer_of(rule) := [value | some value in peer(rule); value != null][0]

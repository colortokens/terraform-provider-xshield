# Says in words which declared rules Xshield has taken out of the group or is waiting to take out, and which
# rules a change needs the group to declare. Empty for a group no change applies to, so its plan shows nothing.

locals {
  review_protocol_aliases = { "6" = "tcp", "17" = "udp", "1" = "icmp", "58" = "icmpv6", "all" = "-1" }
  review_protocol_names   = { tcp = "TCP", udp = "UDP", icmp = "ICMP", icmpv6 = "ICMPv6" }

  review_declared = merge(
    { for key, rule in var.ingress : "ingress/${key}" => rule },
    { for key, rule in var.egress : "egress/${key}" => rule },
  )

  review_revoked             = local.changed ? data.xshield_aws_security_group_rules.this[0].revoked : []
  review_pending             = local.changed ? data.xshield_aws_security_group_rules.this[0].pending : []
  review_reopens             = local.changed ? data.xshield_aws_security_group_rules.this[0].reopens : []
  review_undeclared_pending  = local.changed ? data.xshield_aws_security_group_rules.this[0].undeclared_pending : []
  review_undeclared_restores = local.changed ? data.xshield_aws_security_group_rules.this[0].undeclared_restores : []

  # A declared rule is found by its key. A rule the group no longer declares comes from Xshield with its content.
  review_entries = concat(
    [for key in local.review_revoked : { state = "taken out", key = key, change_set = "", direction = split("/", key)[0], rule = try(local.review_declared[key], null) }],
    [for key in local.review_pending : { state = "waiting", key = key, change_set = "", direction = split("/", key)[0], rule = try(local.review_declared[key], null) }],
    [for reopen in local.review_reopens : { state = "reopens", key = reopen.rule, change_set = reopen.change_set, direction = split("/", reopen.rule)[0], rule = try(local.review_declared[reopen.rule], null) }],
    [for move in local.review_undeclared_pending : { state = "undeclared and waiting", key = "", change_set = move.change_set, direction = move.direction, rule = move }],
    [for move in local.review_undeclared_restores : { state = "undeclared and restored", key = "", change_set = move.change_set, direction = move.direction, rule = move }],
  )

  # Ports and peer of each entry's rule. A key Xshield names that the group does not declare has no rule to word.
  review_facts = [
    for entry in local.review_entries : {
      worded    = entry.rule != null
      toward    = entry.direction == "ingress" ? "from" : "to"
      protocol  = try(lookup(local.review_protocol_aliases, lower(entry.rule.ip_protocol), lower(entry.rule.ip_protocol)), "")
      from_port = try(coalesce(entry.rule.from_port, -1), -1)
      to_port   = try(coalesce(entry.rule.to_port, -1), -1)
      peer = try(coalesce(
        entry.rule.cidr_ipv4,
        entry.rule.cidr_ipv6,
        entry.rule.prefix_list_id == null ? null : "prefix list ${entry.rule.prefix_list_id}",
        entry.rule.referenced_security_group_id == null ? null : "security group ${entry.rule.referenced_security_group_id}",
        "an unnamed address",
      ), "")
    }
  ]
  review_ports = [
    for fact in local.review_facts : (
      fact.protocol == "-1" ? "all traffic" :
      !contains(keys(local.review_protocol_names), fact.protocol) ? "protocol ${fact.protocol}" :
      fact.from_port == -1 || (contains(["tcp", "udp"], fact.protocol) && fact.from_port == 0 && fact.to_port == 65535) ? "all ${local.review_protocol_names[fact.protocol]}" :
      contains(["icmp", "icmpv6"], fact.protocol) ? "${local.review_protocol_names[fact.protocol]} type ${fact.from_port}${fact.to_port == -1 ? "" : " code ${fact.to_port}"}" :
      fact.from_port == fact.to_port || fact.to_port == -1 ? "${local.review_protocol_names[fact.protocol]} ${fact.from_port}" :
      "${local.review_protocol_names[fact.protocol]} ${fact.from_port}-${fact.to_port}"
    )
  ]
  review_rules = [
    for i, entry in local.review_entries : join(" ", compact([
      entry.key == "" ? "" : "rule ${entry.key}",
      !local.review_facts[i].worded ? "" : format(entry.key == "" ? "%s %s %s" : "(%s %s %s)", local.review_ports[i], local.review_facts[i].toward, local.review_facts[i].peer),
    ]))
  ]

  review = [
    for i, entry in local.review_entries : format("Group %s: %s %s", var.group_name, local.review_rules[i], {
      "taken out"               = "is taken out by Xshield."
      "waiting"                 = "is waiting. Xshield takes it out once every workload that keeps it carries its cohort group."
      "reopens"                 = "gives workloads in the group traffic that change set ${entry.change_set} takes from them."
      "undeclared and waiting"  = "is no longer declared, and change set ${entry.change_set} is waiting to take it out. Declare it again, or the workloads that keep it lose it early. Xshield leaves it out once it is safe."
      "undeclared and restored" = "is no longer declared, and the revert of change set ${entry.change_set} puts it back. Declare it again: the revert waits until the group holds it."
    }[entry.state])
  ]
}

output "review" {
  description = "In words: each declared rule Xshield has taken out of the group or is waiting to take out, each declared rule that gives back traffic a change set takes away, and each rule a change set needs declared again. Empty when no approved change applies to the group, or when it leaves every rule as declared."
  value       = tolist(local.review)
}

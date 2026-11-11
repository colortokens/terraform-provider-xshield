# Says in words what the version holds. A root module that exports the review output shows a change as
# sentences under "Changes to Outputs". A plan shows only the sentences that changed, so each one names its group.

locals {
  review_protocol_aliases = { "6" = "tcp", "17" = "udp", "1" = "icmp", "58" = "icmpv6", "all" = "-1" }
  review_protocol_names   = { tcp = "TCP", udp = "UDP", icmp = "ICMP", icmpv6 = "ICMPv6" }
  review_names_per_line   = 5

  review_cohorts   = [for key, group in local.snap.security_groups : key if try(group.tags["ct:kind"], "") == "cohort"]
  review_groups    = concat(local.review_cohorts, [for key in keys(local.snap.security_groups) : key if !contains(local.review_cohorts, key)])
  review_described = slice(local.review_groups, 0, min(var.review_max_groups, length(local.review_groups)))
  review_subjects  = { for key in local.review_described : key => contains(local.review_cohorts, key) ? "Cohort group ${key}" : "Group for ${key}" }

  review_rule_facts = [
    for rule in concat(
      [for rule in values(local.snap.ingress_rules) : merge(rule, { direction = "inbound" })],
      [for rule in values(local.snap.egress_rules) : merge(rule, { direction = "outbound" })],
      ) : {
      group     = rule.security_group
      direction = rule.direction
      protocol  = lookup(local.review_protocol_aliases, lower(rule.ip_protocol), lower(rule.ip_protocol))
      from_port = rule.from_port
      to_port   = rule.to_port
      peer = coalesce(
        rule.cidr_ipv4,
        rule.cidr_ipv6,
        rule.prefix_list_id == null ? null : "prefix list ${rule.prefix_list_id}",
        rule.referenced_security_group_id == null ? null : "security group ${rule.referenced_security_group_id}",
        "an unnamed address",
      )
      # A rule's description ends with a name in brackets: its template, or for a kept rule its customer group.
      label       = try(regex("\\[(.+)\\]\\s*$", rule.description)[0], "")
      kept        = try(rule.tags["ct:origin"], "") == "kept"
      split_group = try(rule.tags["ct:split-group"], "")
      change_set  = try(rule.tags["ct:change-set"], "")
    } if contains(local.review_described, rule.security_group)
  ]

  # A span is a port range as text that sorts in port order. TCP and UDP without ports mean every port.
  review_rules = [
    for rule in local.review_rule_facts : merge(rule, {
      span = contains(["tcp", "udp"], rule.protocol) && (rule.from_port == null || rule.from_port == -1) ? "00000:65535" : format("%05d:%05d", coalesce(rule.from_port, -1), coalesce(rule.to_port, -1))
      note = !rule.kept ? (rule.label == "" ? "" : " (template ${rule.label})") : format(
        ", kept from %s%s",
        rule.label == "" && rule.split_group == "" ? "a customer group" : "customer group ${join(" ", compact([rule.label, rule.label == "" || rule.split_group == "" ? rule.split_group : "(${rule.split_group})"]))}",
        rule.change_set == "" ? "" : " under change set ${rule.change_set}",
      )
    })
  ]

  # One entry for each group, direction, note, peer and protocol, so the ports one peer reaches are worded together.
  review_access = { for rule in local.review_rules : jsonencode([rule.group, rule.direction, rule.note, rule.peer, rule.protocol]) => rule... }
  review_spans = {
    for key, rules in local.review_access : key => [
      for span in sort(distinct(rules[*].span)) : [for port in split(":", span) : parseint(port, 10)]
    ]
  }

  # Ranges that start at port 0, end at port 65535 and leave ports out between them are worded by what they
  # leave out. Any other set of ranges has no gaps here and is worded range by range.
  review_gaps = {
    for key, spans in local.review_spans : key => [
      for i in range(length(spans) - 1) : spans[i][1] + 2 == spans[i + 1][0] ? tostring(spans[i][1] + 1) : "${spans[i][1] + 1}-${spans[i + 1][0] - 1}"
      if contains(["tcp", "udp"], local.review_access[key][0].protocol) && spans[0][0] == 0 && spans[length(spans) - 1][1] == 65535 && alltrue([for j in range(length(spans) - 1) : spans[j][1] + 1 < spans[j + 1][0]])
    ]
  }
  review_port_items = {
    for key, spans in local.review_spans : key => length(local.review_gaps[key]) > 0 ? local.review_gaps[key] : [
      for span in spans : contains(["icmp", "icmpv6"], local.review_access[key][0].protocol) ? (span[1] == -1 ? "type ${span[0]}" : "type ${span[0]} code ${span[1]}") : (span[0] == span[1] ? tostring(span[0]) : "${span[0]}-${span[1]}")
    ]
  }
  review_ports = {
    for key, items in local.review_port_items : key => (
      local.review_access[key][0].protocol == "-1" ? "all traffic" :
      !contains(keys(local.review_protocol_names), local.review_access[key][0].protocol) ? "protocol ${local.review_access[key][0].protocol}" :
      anytrue([for span in local.review_spans[key] : span[0] == -1 || (span[0] == 0 && span[1] == 65535)]) ? "all ${local.review_protocol_names[local.review_access[key][0].protocol]}" :
      format(
        length(local.review_gaps[key]) > 0 ? "all %s except %s" : "%s %s",
        local.review_protocol_names[local.review_access[key][0].protocol],
        join(" and ", compact([join(", ", slice(items, 0, length(items) - 1)), items[length(items) - 1]])),
      )
    )
  }

  # One sentence for each group, direction, ports and note, naming the peers it applies to. The key puts a
  # group's sentences in order: inbound first, then by protocol and lowest port.
  review_peers = {
    for key, rules in local.review_access :
    jsonencode([rules[0].group, rules[0].direction, format("%s %05d", rules[0].protocol, max(0, local.review_spans[key][0][0])), local.review_ports[key], rules[0].note]) => rules[0].peer...
  }
  review_peer_names = {
    for key, peers in local.review_peers : key => length(peers) > local.review_names_per_line ? concat(slice(sort(peers), 0, local.review_names_per_line), ["${length(peers) - local.review_names_per_line} more"]) : sort(peers)
  }
  review_rule_lines = {
    for key, names in local.review_peer_names : jsondecode(key)[0] => format(
      "%s allows %s %s %s%s.",
      local.review_subjects[jsondecode(key)[0]],
      jsondecode(key)[3],
      jsondecode(key)[1] == "inbound" ? "from" : "to",
      join(" and ", compact([join(", ", slice(names, 0, length(names) - 1)), names[length(names) - 1]])),
      jsondecode(key)[4],
    )...
  }

  review_interfaces      = { for attachment in values(local.snap.interface_attachments) : attachment.security_group => attachment.network_interface_id... }
  review_interface_owner = { for attachment in values(local.snap.interface_attachments) : attachment.network_interface_id => attachment.security_group... if !contains(local.review_cohorts, attachment.security_group) }
  review_handles = {
    for pair in flatten([for entry in values(local.snap.directory) : [for key in entry.security_groups : { group = key, handle = entry.handle }]]) : pair.group => pair.handle...
  }

  # The workloads a group's first sentence names. A cohort group goes on the workloads that keep the access: an
  # interface is named by its instance where the version also holds that instance's own group. Any other group
  # names the handles whose own workspaces attach it.
  review_carriers = {
    for key in local.review_described : key => sort(distinct(concat(
      [for interface in lookup(local.review_interfaces, key, []) : try(local.review_interface_owner[interface][0], "network interface ${interface}") if contains(local.review_cohorts, key)],
      lookup(local.review_handles, key, []),
    )))
  }
  review_carrier_names = {
    for key, carriers in local.review_carriers : key => length(carriers) > local.review_names_per_line ? concat(slice(carriers, 0, local.review_names_per_line), ["${length(carriers) - local.review_names_per_line} more"]) : carriers
  }
  review_carried_by = {
    for key, names in local.review_carrier_names : key => length(names) == 0 ? "" : join(" and ", compact([join(", ", slice(names, 0, length(names) - 1)), names[length(names) - 1]]))
  }
  review_attached = {
    for key in local.review_described : key => compact([
      length(lookup(local.review_interfaces, key, [])) == 0 ? "" : "by this workspace to ${length(local.review_interfaces[key])} network ${length(local.review_interfaces[key]) == 1 ? "interface" : "interfaces"}",
      local.review_carried_by[key] == "" ? "" : "by the ${length(local.review_carriers[key]) == 1 ? "workspace that owns" : "workspaces that own"} ${local.review_carried_by[key]}",
    ])
  }
  review_headers = {
    for key in local.review_described : key => (
      contains(local.snap.withdrawing, key) ? "${local.review_subjects[key]} is being withdrawn. Policy no longer uses it, and it keeps its rules until Xshield sees it detached." :
      contains(local.review_cohorts, key) ? format(
        "%s %s. It keeps access that %s gives up%s.",
        local.review_subjects[key],
        local.review_carried_by[key] == "" ? "is on no workload in this version" : "is for ${local.review_carried_by[key]}",
        try("customer group ${local.snap.security_groups[key].tags["ct:split-group"]}", "a customer group"),
        try(" under change set ${local.snap.security_groups[key].tags["ct:change-set"]}", ""),
      ) :
      length(local.review_attached[key]) == 0 ? "${local.review_subjects[key]} is attached to nothing in this version." :
      "${local.review_subjects[key]} is attached ${join(" and ", local.review_attached[key])}."
    )
  }

  review = tolist(!local.snap.published ? ["Xshield has published nothing for ${local.account_id}/${local.region}."] : concat(
    flatten([for key in local.review_described : concat([local.review_headers[key]], lookup(local.review_rule_lines, key, []))]),
    length(local.review_groups) == length(local.review_described) ? [] : [
      "${length(local.review_groups) - length(local.review_described)} more ${length(local.review_groups) - length(local.review_described) == 1 ? "group is" : "groups are"} not described here. Raise review_max_groups to describe them.",
    ],
    [format(
      "Version %s holds %d %s, %d %s and %d interface %s for %s/%s.",
      substr(local.snap.version, 0, 12),
      length(local.review_groups), length(local.review_groups) == 1 ? "group" : "groups",
      length(local.snap.ingress_rules) + length(local.snap.egress_rules), length(local.snap.ingress_rules) + length(local.snap.egress_rules) == 1 ? "rule" : "rules",
      length(local.snap.interface_attachments), length(local.snap.interface_attachments) == 1 ? "attachment" : "attachments",
      local.account_id, local.region,
    )],
  ))
}

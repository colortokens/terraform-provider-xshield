# Says in words what the version holds. A root module that exports the review output shows a change as
# sentences under "Changes to Outputs". A plan shows only the sentences that changed, so each one names its group.
# Azure applies a group's rules in priority order and the first that matches decides, so a group's sentences keep it.

locals {
  review_protocol_names = { tcp = "TCP", udp = "UDP", icmp = "ICMP", esp = "ESP", ah = "AH" }
  review_names_per_line = 5

  review_groups    = keys(local.snap.network_security_groups)
  review_described = slice(local.review_groups, 0, min(var.review_max_groups, length(local.review_groups)))

  review_interfaces = { for association in values(local.snap.interface_associations) : association.network_security_group => association.network_interface_id... }
  review_subnets    = { for association in values(local.snap.subnet_associations) : association.network_security_group => association.subnet_id... }
  review_assets = {
    for pair in flatten([for id, asset in local.snap.assets : [for key in asset.network_security_groups : { group = key, asset = id }]]) : pair.group => pair.asset...
  }

  # Each list a sentence names, already worded: a network interface by the last segment of its ID, a subnet with its
  # virtual network; an address as it is, any address as anywhere, and any other prefix, such as AzureLoadBalancer, as
  # a service tag.
  review_names = {
    for key in local.review_described : key => {
      interfaces = [for id in sort(lookup(local.review_interfaces, key, [])) : regex("[^/]+$", id)]
      subnets    = [for id in sort(lookup(local.review_subnets, key, [])) : try(format("%[2]s of virtual network %[1]s", regex("(?i)/virtualNetworks/([^/]+)/subnets/([^/]+)$", id)...), id)]
      owners     = sort(lookup(local.review_assets, key, []))
      rules = [
        for i, rule in local.snap.network_security_groups[key].security_rules : {
          order    = format("%d %05d %05d", lower(rule.direction) == "inbound" ? 0 : 1, rule.priority, i)
          inbound  = lower(rule.direction) == "inbound"
          access   = lower(rule.access) == "allow" ? "allows" : "denies"
          protocol = lower(rule.protocol)
          ports    = coalescelist(compact(concat([rule.destination_port_range], rule.destination_port_ranges)), ["*"])
          source = [
            for prefix in sort(coalescelist(compact(concat([rule.source_address_prefix], rule.source_address_prefixes)), ["*"])) :
            prefix == "*" ? "anywhere" : can(regex("^[0-9a-fA-F:.]+(/[0-9]+)?$", prefix)) ? prefix : "service tag ${prefix}"
          ]
          destination = [
            for prefix in sort(coalescelist(compact(concat([rule.destination_address_prefix], rule.destination_address_prefixes)), ["*"])) :
            prefix == "*" ? "anywhere" : can(regex("^[0-9a-fA-F:.]+(/[0-9]+)?$", prefix)) ? prefix : "service tag ${prefix}"
          ]
          test = startswith(rule.name, "CT-Test-Rule-")
        }
      ]
    }
  }

  # Each list joined as a sentence names it: at most review_names_per_line names, then how many more.
  review_shown = {
    for key, names in local.review_names : key => {
      for list, items in merge(
        { interfaces = names.interfaces, subnets = names.subnets, owners = names.owners },
        merge([for rule in names.rules : { "${rule.order} source" = rule.source, "${rule.order} destination" = rule.destination, "${rule.order} ports" = rule.ports }]...),
        ) : list => [
        for shown in [length(items) > local.review_names_per_line ? concat(slice(items, 0, local.review_names_per_line), ["${length(items) - local.review_names_per_line} more"]) : items] :
        length(shown) == 0 ? "" : join(" and ", compact([join(", ", slice(shown, 0, length(shown) - 1)), shown[length(shown) - 1]]))
      ][0]
    }
  }

  review_headers = {
    for key, names in local.review_names : key => format(
      "Group %s is associated with %s%s.",
      key,
      coalesce(join(" and ", compact([
        length(names.interfaces) == 0 ? "" : "${length(names.interfaces) == 1 ? "network interface" : "network interfaces"} ${local.review_shown[key].interfaces}",
        length(names.subnets) == 0 ? "" : "${length(names.subnets) == 1 ? "subnet" : "subnets"} ${local.review_shown[key].subnets}",
      ])), "nothing in this version"),
      length(names.owners) == 0 ? "" : ", for ${length(names.owners) == 1 ? "asset" : "assets"} ${local.review_shown[key].owners}",
    )
  }

  review_rule_lines = {
    for key, names in local.review_names : key => [
      for rule in [for order in sort(names.rules[*].order) : names.rules[tonumber(split(" ", order)[2])]] : format(
        "Group %s %s %s %s%s.",
        key,
        rule.access,
        rule.protocol == "*" ? (
          contains(rule.ports, "*") ? "all ${rule.inbound ? "inbound" : "outbound"} traffic" :
          "${rule.inbound ? "inbound" : "outbound"} traffic on ${length(rule.ports) == 1 ? "port" : "ports"} ${local.review_shown[key]["${rule.order} ports"]}"
          ) : (
          contains(rule.ports, "*") || !contains(["tcp", "udp"], rule.protocol) ? "all ${rule.inbound ? "inbound" : "outbound"} ${lookup(local.review_protocol_names, rule.protocol, "protocol ${rule.protocol}")}" :
          "${rule.inbound ? "inbound" : "outbound"} ${local.review_protocol_names[rule.protocol]} ${local.review_shown[key]["${rule.order} ports"]}"
        ),
        join(" ", compact([
          rule.inbound || rule.source != ["anywhere"] ? "from ${local.review_shown[key]["${rule.order} source"]}" : "",
          !rule.inbound || rule.destination != ["anywhere"] ? "to ${local.review_shown[key]["${rule.order} destination"]}" : "",
        ])),
        rule.test ? ", logged as traffic enforce would block" : "",
      )
    ]
  }

  review_rule_count = sum(concat([0], [for group in values(local.snap.network_security_groups) : length(group.security_rules)]))
  review_counts = [
    "${length(local.review_groups)} ${length(local.review_groups) == 1 ? "group" : "groups"}",
    "${local.review_rule_count} ${local.review_rule_count == 1 ? "rule" : "rules"}",
    "${length(local.snap.interface_associations)} interface ${length(local.snap.interface_associations) == 1 ? "association" : "associations"}",
    "${length(local.snap.subnet_associations)} subnet ${length(local.snap.subnet_associations) == 1 ? "association" : "associations"}",
  ]

  review = tolist(!local.snap.published ? ["Xshield has published nothing for ${local.subscription_id}/${var.region}."] : concat(
    flatten([for key in local.review_described : concat([local.review_headers[key]], local.review_rule_lines[key])]),
    length(local.review_groups) == length(local.review_described) ? [] : [
      "${length(local.review_groups) - length(local.review_described)} more ${length(local.review_groups) - length(local.review_described) == 1 ? "group is" : "groups are"} not described here. Raise review_max_groups to describe them.",
    ],
    [format(
      "Version %s holds %s for %s/%s.",
      substr(local.snap.version, 0, 12),
      join(" and ", [join(", ", slice(local.review_counts, 0, length(local.review_counts) - 1)), local.review_counts[length(local.review_counts) - 1]]),
      local.subscription_id, var.region,
    )],
  ))
}

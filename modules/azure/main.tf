# Applies the Azure resources Xshield rendered for one subscription and region. Every decision is in the snapshot: this
# module only creates what it lists, keyed as it lists it.

data "azurerm_client_config" "current" {}

locals {
  subscription_id = coalesce(var.cloud_account_id, data.azurerm_client_config.current.subscription_id)
  snap            = data.xshield_azure_enforcement_snapshot.this
  workspace       = coalesce(var.workspace, "xshield-enforcement-${local.subscription_id}-${var.region}")
  # The tag Xshield and its cloud connector mark a pipeline's network security groups with.
  xshield_delivery_tag = { "ct:delivery" = "pipeline" }
}

data "xshield_azure_enforcement_snapshot" "this" {
  cloud_account_id = local.subscription_id
  region           = var.region
  version          = var.snapshot_version
  enforcement_plan = true

  lifecycle {
    postcondition {
      condition     = lower(self.cloud_account_id) == lower(data.azurerm_client_config.current.subscription_id)
      error_message = "This snapshot is for subscription ${self.cloud_account_id}, but the azurerm provider is configured for ${data.azurerm_client_config.current.subscription_id}. Point the azurerm provider at the subscription the snapshot is for."
    }
  }
}

# Xshield never unpublishes a subscription: it withdraws by publishing an empty version. So with nothing published,
# network security groups it rendered for a pipeline in this region mean the provider is reading another tenant or
# endpoint, and applying would remove them.
data "azurerm_resources" "rendered" {
  count = local.snap.published ? 0 : 1

  type          = "Microsoft.Network/networkSecurityGroups"
  required_tags = local.xshield_delivery_tag

  lifecycle {
    postcondition {
      condition     = length([for group in self.resources : group.id if replace(lower(group.location), " ", "") == var.region]) == 0
      error_message = "Xshield has published nothing for ${local.subscription_id}/${var.region}, yet the subscription holds network security groups Xshield rendered for a pipeline there (${join(", ", [for group in self.resources : group.name if replace(lower(group.location), " ", "") == var.region])}), and applying would remove them. Check that the xshield provider's endpoint and API key are for the tenant that published them. To remove Xshield's groups on purpose, remove this module from the configuration."
    }
  }
}

# With nothing published the plan reads "No changes", which looks the same as a subscription whose policy the provider
# cannot see, so the run says which it is.
check "xshield_published" {
  assert {
    condition     = local.snap.published
    error_message = "Xshield has published nothing for ${local.subscription_id}/${var.region}, so this run creates nothing. If the subscription should have policy there, check in Xshield that it is set to pipeline delivery and has a deployed policy, and check that the xshield provider's endpoint and API key are for the tenant that owns the subscription."
  }
}

# A resource group holds one network security group per name, whatever its region, so the name of each group the last
# receipt does not hold is looked up, and a group already holding it stops the plan unless it carries Xshield's
# ct:delivery tag: one an apply created before it failed without a receipt, or whose state was lost. azurerm would
# otherwise refuse the group and suggest importing the holder, which would give a group of yours Xshield's rules.
data "xshield_azure_enforcement_status" "this" {
  count = local.snap.published && length(local.snap.network_security_groups) > 0 ? 1 : 0

  cloud_account_id = local.subscription_id
  region           = var.region
}

locals {
  applied_network_security_groups = try(data.xshield_azure_enforcement_status.this[0].applied_network_security_groups, {})
  new_network_security_groups     = { for key, group in local.snap.network_security_groups : key => group if lookup(local.applied_network_security_groups, key, null) == null }
}

# azurerm has no resource that leaves a group's other rules alone: a group's rules are given either inline or as rule
# resources, and using both on one group makes each overwrite the other's rules. So with enable_exclusive_rules off,
# the rules a group already holds that are not Xshield's are read back and given again with Xshield's. Xshield names
# its rules CT-Rule- or CT-Test-Rule-, as the cloud connector does, so a rule named otherwise is someone else's.
# Read by resource group: Xshield's groups are created in these, so an apply needs them anyway.
data "azurerm_resources" "network_security_groups" {
  for_each = length(local.new_network_security_groups) > 0 || !var.enable_exclusive_rules && length(local.snap.network_security_groups) > 0 ? toset([for group in local.snap.network_security_groups : lower(group.resource_group_name)]) : toset([])

  type                = "Microsoft.Network/networkSecurityGroups"
  resource_group_name = each.key
}

locals {
  present_network_security_groups = {
    for group in flatten([for resource_group, read in data.azurerm_resources.network_security_groups : [for group in read.resources : group if lower(group.resource_group_name) == resource_group]]) :
    lower("${group.resource_group_name}/${group.name}") => group
  }
  network_security_group_name_holders = {
    for key, group in local.new_network_security_groups : key => local.present_network_security_groups[lower("${group.resource_group_name}/${group.name}")]
    if contains(keys(local.present_network_security_groups), lower("${group.resource_group_name}/${group.name}")) && try(local.present_network_security_groups[lower("${group.resource_group_name}/${group.name}")].tags["ct:delivery"], "") != local.xshield_delivery_tag["ct:delivery"]
  }
}

data "azurerm_network_security_group" "kept_rules" {
  for_each = { for key, group in local.snap.network_security_groups : key => group if !var.enable_exclusive_rules && contains(keys(local.present_network_security_groups), lower("${group.resource_group_name}/${group.name}")) }

  name                = each.value.name
  resource_group_name = each.value.resource_group_name
}

locals {
  kept_rules = {
    for key, group in data.azurerm_network_security_group.kept_rules : key => [
      for rule in group.security_rule : rule if !startswith(rule.name, "CT-Rule-") && !startswith(rule.name, "CT-Test-Rule-")
    ]
  }
  # Azure takes one rule for each priority and direction in a group.
  kept_rule_conflicts = {
    for key, rules in local.kept_rules : key => [
      for rule in rules : "${rule.name} (${rule.direction} ${rule.priority})"
      if contains([for xshield in local.snap.network_security_groups[key].security_rules : lower("${xshield.direction}/${xshield.priority}")], lower("${rule.direction}/${rule.priority}"))
    ]
  }
}

resource "azurerm_network_security_group" "this" {
  for_each = local.snap.network_security_groups

  name                = each.value.name
  resource_group_name = each.value.resource_group_name
  location            = each.value.location
  tags                = merge(var.tags, each.value.tags)

  # Given as an argument rather than as blocks, the rules are the group's whole rule set, so the next apply removes a
  # rule added to the group outside Terraform unless it is kept. The three fields Xshield never sets take the values
  # Azure reads back.
  security_rule = concat(
    [for rule in each.value.security_rules : merge(rule, {
      description                                = ""
      source_application_security_group_ids      = []
      destination_application_security_group_ids = []
    })],
    try(local.kept_rules[each.key], []),
  )

  lifecycle {
    precondition {
      condition     = !contains(keys(local.network_security_group_name_holders), each.key)
      error_message = "Network security group ${each.value.name} already exists in resource group ${each.value.resource_group_name} (${try(local.network_security_group_name_holders[each.key].id, "")}) and is not Xshield's, so Azure would refuse Xshield's group ${each.key} under that name. The plan stopped and nothing was applied. Do not import the existing group: this module would replace its rules with Xshield's. Xshield gives its group another name once the cloud connector's next observation of ${local.subscription_id}/${var.region} shows yours, so plan again then. If a later plan still stops here, move your group to another resource group, or replace it with a group under another name, as Azure cannot rename a network security group."
    }
    precondition {
      condition     = length(try(local.kept_rule_conflicts[each.key], [])) == 0
      error_message = "Network security group ${each.value.name} holds rules added outside Terraform at a priority and direction one of Xshield's rules takes: ${join(", ", try(local.kept_rule_conflicts[each.key], []))}. Azure takes one rule for each priority and direction in a group, so move each to a priority Xshield's rules leave free, or set enable_exclusive_rules = true for the apply to remove them."
    }
  }
}

# Every association below reads its group's ID from this map, which Terraform builds once. Indexing the resource with a
# key from each.value builds all of its instances for every reference instead.
locals {
  network_security_group_ids = { for key, group in azurerm_network_security_group.this : key => group.id }
}

# A workload's network interface can go before discovery tells Xshield, so an association is planned only while its
# network interface exists: a deleted one never fails the apply.
data "azurerm_resources" "network_interfaces" {
  count = length(local.snap.interface_associations) + length(local.snap.handover_interface_associations) + length(local.snap.held_interface_associations) + length(local.snap.released_interface_associations) + length(local.snap.contained_interface_associations) > 0 ? 1 : 0

  type = "Microsoft.Network/networkInterfaces"
}

locals {
  present_interfaces     = { for interface in try(data.azurerm_resources.network_interfaces[0].resources, []) : lower(interface.id) => true }
  interface_associations = { for key, association in local.snap.interface_associations : key => association if lookup(local.present_interfaces, lower(association.network_interface_id), false) }

  leaving_interfaces = merge(
    { for key, interface_id in local.snap.released_interface_associations : key => interface_id if lookup(local.present_interfaces, lower(interface_id), false) },
    { for key, held in local.snap.held_interface_associations : key => held.level_id if lookup(local.present_interfaces, lower(held.level_id), false) },
  )
  leaving_subnets = merge(
    { for key, subnet_id in local.snap.released_subnet_associations : key => subnet_id if contains(local.present_subnets, lower(subnet_id)) },
    { for key, held in local.snap.held_subnet_associations : key => held.level_id if contains(local.present_subnets, lower(held.level_id)) },
  )
}

# A subnet can go too, with its virtual network once its workloads are gone, so an association is planned, and a subnet
# read, only while its subnet exists. Azure lists no subnet on its own: they are read from the virtual networks that exist.
locals {
  subnet_levels = toset([for id in concat(
    [for association in local.snap.subnet_associations : association.subnet_id],
    values(local.snap.released_subnet_associations),
    [for held in local.snap.held_subnet_associations : held.level_id],
    [for contained in local.snap.contained_subnet_associations : contained.level_id],
    [for association in local.snap.handover_subnet_associations : association.subnet_id],
  ) : lower(id)])
  subnet_virtual_networks = toset([for id in local.subnet_levels : join("/", slice(split("/", id), 0, 9))])
}

data "azurerm_resources" "virtual_networks" {
  count = length(local.subnet_levels) > 0 ? 1 : 0

  type = "Microsoft.Network/virtualNetworks"
}

data "azurerm_virtual_network" "subnet_levels" {
  for_each = { for network in try(data.azurerm_resources.virtual_networks[0].resources, []) : lower(network.id) => network if contains(local.subnet_virtual_networks, lower(network.id)) }

  name                = each.value.name
  resource_group_name = each.value.resource_group_name
}

locals {
  present_subnets     = toset(flatten([for id, network in data.azurerm_virtual_network.subnet_levels : [for name in network.subnets : lower("${id}/subnets/${name}")]]))
  subnet_associations = { for key, association in local.snap.subnet_associations : key => association if contains(local.present_subnets, lower(association.subnet_id)) }
  contained_levels    = { for key, contained in local.snap.contained_subnet_associations : key => contained if contains(local.present_subnets, lower(contained.level_id)) }
  handover_subnets    = { for key, association in local.snap.handover_subnet_associations : key => association if contains(local.present_subnets, lower(association.subnet_id)) }
}

# Xshield's groups are the ones tagged for a pipeline. Their names are no guide, as a name template can name them anything.
data "azurerm_resources" "xshield_network_security_groups" {
  count = length(local.leaving_interfaces) + length(local.leaving_subnets) + length(local.subnet_associations) > 0 ? 1 : 0

  type          = "Microsoft.Network/networkSecurityGroups"
  required_tags = local.xshield_delivery_tag
}

locals {
  # A level that carries no group reads back as "" or null, which coalesce turns to "-": taking the association off it takes
  # nothing of yours.
  xshields_or_no_group = merge({ "-" = true }, { for group in try(data.azurerm_resources.xshield_network_security_groups[0].resources, []) : lower(group.id) => true })

  next_observation_advice = var.snapshot_version == null ? ": plan again after that." : ", in a version newer than the one snapshot_version pins (${var.snapshot_version}), so this stop stays until you pin that newer version or remove the pin."
}

# Azure removes an association by taking whatever group its network interface or subnet carries off it. So each one
# this version stops wanting is read first: a removal is refused while the level carries a group other than Xshield's,
# and one Xshield holds stays in the state, unchanged, while its level carries such a group.
data "azurerm_network_interface" "leaving" {
  for_each = local.leaving_interfaces

  name                = split("/", each.value)[8]
  resource_group_name = split("/", each.value)[4]

  lifecycle {
    postcondition {
      condition     = contains(keys(local.snap.held_interface_associations), each.key) || lookup(local.xshields_or_no_group, lower(coalesce(self.network_security_group_id, "-")), false)
      error_message = "Network interface ${self.name} now carries network security group ${element(split("/", coalesce(self.network_security_group_id, "-")), -1)} in place of Xshield's ${each.key}. Azure removes an association by clearing the interface's group, so removing Xshield's would take yours off it. Xshield holds the association once it next observes the subscription${local.next_observation_advice}"
    }
  }
}

data "azurerm_subnet" "leaving" {
  for_each = local.leaving_subnets

  name                 = split("/", each.value)[10]
  virtual_network_name = split("/", each.value)[8]
  resource_group_name  = split("/", each.value)[4]

  lifecycle {
    postcondition {
      condition     = contains(keys(local.snap.held_subnet_associations), each.key) || lookup(local.xshields_or_no_group, lower(coalesce(self.network_security_group_id, "-")), false)
      error_message = "Subnet ${self.name} now carries network security group ${element(split("/", coalesce(self.network_security_group_id, "-")), -1)} in place of Xshield's ${each.key}. Azure removes an association by clearing the subnet's group, so removing Xshield's would take yours off it. Xshield holds the association once it next observes the subscription${local.next_observation_advice}"
    }
  }
}

# azurerm reads a subnet association's group back from the subnet, so one whose subnet now carries another group plans a
# replacement, and Azure deletes the association by clearing the subnet's group. So each subnet an association wants is read
# first, and the plan stops while it carries a group that is neither Xshield's nor the one the association wants.
data "azurerm_subnet" "associated" {
  for_each = local.subnet_associations

  name                 = split("/", each.value.subnet_id)[10]
  virtual_network_name = split("/", each.value.subnet_id)[8]
  resource_group_name  = split("/", each.value.subnet_id)[4]

  lifecycle {
    postcondition {
      condition     = lookup(local.xshields_or_no_group, lower(coalesce(self.network_security_group_id, "-")), false) || lower(coalesce(self.network_security_group_id, "-")) == local.planned_network_security_group_ids[each.value.network_security_group]
      error_message = "Subnet ${self.name} now carries network security group ${element(split("/", coalesce(self.network_security_group_id, "-")), -1)} in place of Xshield's ${each.value.network_security_group}. azurerm would replace the association, and Azure replaces one by clearing the subnet's group, so applying would take yours off it. The plan stopped and nothing was applied. Xshield takes the change into account once the cloud connector next observes the subscription${local.next_observation_advice}"
    }
  }
}

locals {
  held_interfaces = {
    for key, held in local.snap.held_interface_associations : key => { level_id = held.level_id, network_security_group_id = held.network_security_group_id }
    if contains(keys(local.leaving_interfaces), key) && !lookup(local.xshields_or_no_group, lower(coalesce(try(data.azurerm_network_interface.leaving[key].network_security_group_id, null), "-")), false)
  }
  # azurerm reads a subnet association's group back from the subnet, unlike an interface association's, so a held subnet
  # association is given the group the subnet carries now, which its state then holds.
  held_subnets = {
    for key, held in local.snap.held_subnet_associations : key => { level_id = held.level_id, network_security_group_id = data.azurerm_subnet.leaving[key].network_security_group_id }
    if contains(keys(local.leaving_subnets), key) && !lookup(local.xshields_or_no_group, lower(coalesce(try(data.azurerm_subnet.leaving[key].network_security_group_id, null), "-")), false)
  }
}

# Xshield's cloud connector contains a workload by putting a group of its own on the level in place of Xshield's, and puts
# Xshield's back when it reverts, so an association of a contained workload stays in the state unchanged and none is created.
data "azurerm_subnet" "contained" {
  for_each = local.contained_levels

  name                 = split("/", each.value.level_id)[10]
  virtual_network_name = split("/", each.value.level_id)[8]
  resource_group_name  = split("/", each.value.level_id)[4]
}

locals {
  contained_interfaces = {
    for key, contained in local.snap.contained_interface_associations : key => { level_id = contained.level_id, network_security_group_id = contained.network_security_group_id }
    if lookup(local.present_interfaces, lower(contained.level_id), false)
  }
  contained_subnets = {
    for key, contained in local.contained_levels : key => {
      level_id                  = contained.level_id
      network_security_group_id = coalesce(data.azurerm_subnet.contained[key].network_security_group_id, contained.network_security_group_id)
    }
  }
}

# The cloud connector enforced at a handover level with a group of its own while the level had none. Creating the
# association there would clear the connector's group until the apply ends, so the apply creates only the group, and once
# the receipt reaches Xshield the connector puts that group in place of its own in a single change. The association is
# then taken over: imported, by the import blocks of handover.tf, where the level carries the group, or created where
# the level carries none. While the level still carries the connector's group the apply leaves it alone.
locals {
  handover_interfaces = { for key, association in local.snap.handover_interface_associations : key => association if lookup(local.present_interfaces, lower(association.network_interface_id), false) }
  # A group created by this apply has no ID until it is created, and Azure builds a group's ID from its name.
  planned_network_security_group_ids = {
    for key, group in local.snap.network_security_groups : key => lower("/subscriptions/${local.subscription_id}/resourceGroups/${group.resource_group_name}/providers/Microsoft.Network/networkSecurityGroups/${group.name}")
  }
}

data "azurerm_network_interface" "handover" {
  for_each = local.handover_interfaces

  name                = split("/", each.value.network_interface_id)[8]
  resource_group_name = split("/", each.value.network_interface_id)[4]
}

data "azurerm_subnet" "handover" {
  for_each = local.handover_subnets

  name                 = split("/", each.value.subnet_id)[10]
  virtual_network_name = split("/", each.value.subnet_id)[8]
  resource_group_name  = split("/", each.value.subnet_id)[4]
}

locals {
  handover_interface_groups = { for key, interface in data.azurerm_network_interface.handover : key => lower(coalesce(interface.network_security_group_id, "-")) }
  handover_subnet_groups    = { for key, subnet in data.azurerm_subnet.handover : key => lower(coalesce(subnet.network_security_group_id, "-")) }

  handed_over_interfaces = {
    for key, association in local.handover_interfaces : key => association
    if contains(["-", local.planned_network_security_group_ids[association.network_security_group]], local.handover_interface_groups[key])
  }
  handed_over_subnets = {
    for key, association in local.handover_subnets : key => association
    if contains(["-", local.planned_network_security_group_ids[association.network_security_group]], local.handover_subnet_groups[key])
  }
  awaiting_handover = concat(
    [for key, association in local.handover_interfaces : split("/", association.network_interface_id)[8] if !contains(keys(local.handed_over_interfaces), key)],
    [for key, association in local.handover_subnets : split("/", association.subnet_id)[10] if !contains(keys(local.handed_over_subnets), key)],
  )
}

check "xshield_handover" {
  assert {
    condition     = length(local.awaiting_handover) == 0
    error_message = "The cloud connector's own network security group is still on ${join(", ", local.awaiting_handover)}. Once this apply's receipt reaches Xshield, the connector puts Xshield's group in its place, and the next apply takes the association over."
  }
}

resource "azurerm_network_interface_security_group_association" "this" {
  for_each = merge(
    { for key, association in local.interface_associations : key => { level_id = association.network_interface_id, network_security_group_id = local.network_security_group_ids[association.network_security_group] } },
    { for key, association in local.handed_over_interfaces : key => { level_id = association.network_interface_id, network_security_group_id = local.network_security_group_ids[association.network_security_group] } },
    local.held_interfaces,
    local.contained_interfaces,
  )

  network_interface_id      = each.value.level_id
  network_security_group_id = each.value.network_security_group_id
}

resource "azurerm_subnet_network_security_group_association" "this" {
  for_each = merge(
    { for key, association in local.subnet_associations : key => { level_id = association.subnet_id, network_security_group_id = local.network_security_group_ids[association.network_security_group] } },
    { for key, association in local.handed_over_subnets : key => { level_id = association.subnet_id, network_security_group_id = local.network_security_group_ids[association.network_security_group] } },
    local.held_subnets,
    local.contained_subnets,
  )

  subnet_id                 = each.value.level_id
  network_security_group_id = each.value.network_security_group_id
}

locals {
  customer_network_security_groups_wanted = local.snap.customer_network_security_groups
}

# A group of yours can be deleted before discovery tells Xshield, so it is read, and given rules, only while Azure lists it.
data "azurerm_resources" "customer_network_security_groups" {
  count = length(local.customer_network_security_groups_wanted) > 0 ? 1 : 0

  type = "Microsoft.Network/networkSecurityGroups"
}

locals {
  present_customer_network_security_groups = toset([for group in try(data.azurerm_resources.customer_network_security_groups[0].resources, []) : lower(group.id)])
  customer_network_security_groups         = { for key, group in local.customer_network_security_groups_wanted : key => group if contains(local.present_customer_network_security_groups, lower(group.id)) }
  unlisted_customer_network_security_groups = [
    for key, group in local.customer_network_security_groups_wanted : "${group.name} in resource group ${group.resource_group_name}"
    if !contains(keys(local.customer_network_security_groups), key)
  ]
}

check "xshield_customer_groups_listed" {
  assert {
    condition     = length(local.unlisted_customer_network_security_groups) == 0
    error_message = "Xshield writes workload rules into network security groups of yours that Azure does not list to this run's identity: ${join(", ", local.unlisted_customer_network_security_groups)}. Each was deleted, or the identity cannot read it, so this apply adds no rule to it. If a group exists, give the run's identity read access to it."
  }
}

data "azurerm_network_security_group" "customer" {
  for_each = local.customer_network_security_groups

  name                = each.value.name
  resource_group_name = each.value.resource_group_name
}

# The rules the group holds now keep Xshield's rules at the priorities they hold, and give a moved or new one a priority
# no rule holds, as Azure refuses two rules at one priority and direction and applies rule resources in no set order.
data "xshield_azure_security_rules" "customer" {
  for_each = local.customer_network_security_groups

  cloud_account_id          = local.snap.cloud_account_id
  region                    = var.region
  version                   = local.snap.version
  network_security_group_id = each.value.id
  current_security_rules    = [for rule in data.azurerm_network_security_group.customer[each.key].security_rule : { name = rule.name, priority = rule.priority, direction = rule.direction }]
}

locals {
  customer_security_rules = merge([
    for key, rules in data.xshield_azure_security_rules.customer : {
      for rule in rules.xshield_security_rules : "${key}/${rule.name}" => merge(rule, {
        network_security_group_name = local.customer_network_security_groups[key].name
        resource_group_name         = local.customer_network_security_groups[key].resource_group_name
      })
    }
  ]...)
}

resource "azurerm_network_security_rule" "customer" {
  for_each = local.customer_security_rules

  name                         = each.value.name
  network_security_group_name  = each.value.network_security_group_name
  resource_group_name          = each.value.resource_group_name
  priority                     = each.value.priority
  direction                    = each.value.direction
  access                       = each.value.access
  protocol                     = each.value.protocol
  source_address_prefix        = each.value.source_address_prefix != "" ? each.value.source_address_prefix : null
  source_address_prefixes      = length(each.value.source_address_prefixes) > 0 ? each.value.source_address_prefixes : null
  destination_address_prefix   = each.value.destination_address_prefix != "" ? each.value.destination_address_prefix : null
  destination_address_prefixes = length(each.value.destination_address_prefixes) > 0 ? each.value.destination_address_prefixes : null
  source_port_range            = each.value.source_port_range != "" ? each.value.source_port_range : null
  source_port_ranges           = length(each.value.source_port_ranges) > 0 ? each.value.source_port_ranges : null
  destination_port_range       = each.value.destination_port_range != "" ? each.value.destination_port_range : null
  destination_port_ranges      = length(each.value.destination_port_ranges) > 0 ? each.value.destination_port_ranges : null
}

# Azure gives a group or association recreated under the same name its old ID, so an apply that restores one changes
# nothing the receipt sends. One record per group is replaced whenever the apply creates, replaces or updates the group or
# its association: an ID unknown until apply catches one created, and replace_triggered_by the group updated in place, such
# as one whose removed rule is restored. An association has nothing to update in place. A new record ID sends the receipt
# again, so Xshield observes the restored state at once.
resource "terraform_data" "xshield_applied_resources" {
  for_each = local.snap.published ? local.snap.network_security_groups : {}

  triggers_replace = [
    local.network_security_group_ids[each.key],
    try(azurerm_subnet_network_security_group_association.this[each.key].id, null),
    try(azurerm_network_interface_security_group_association.this[each.key].id, null),
  ]

  lifecycle {
    replace_triggered_by = [azurerm_network_security_group.this[each.key]]
  }
}

# As above, for Xshield's rules in your groups: a rule recreated under its name gets its old ID back.
resource "terraform_data" "xshield_applied_customer_rules" {
  count = local.snap.published && length(local.customer_security_rules) > 0 ? 1 : 0

  triggers_replace = [for key in sort(keys(azurerm_network_security_rule.customer)) : azurerm_network_security_rule.customer[key].id]

  lifecycle {
    replace_triggered_by = [azurerm_network_security_rule.customer]
  }
}

# Tells Xshield the version is applied, and which resource it created for each key, so its status shows the subscription
# and region converged, and a lost state can be rebuilt from the receipt.
resource "xshield_azure_enforcement_receipt" "this" {
  count = local.snap.published ? 1 : 0

  cloud_account_id = local.snap.cloud_account_id
  region           = local.snap.region
  workspace        = local.workspace
  snapshot_version = local.snap.version
  exclusive_rules  = var.enable_exclusive_rules
  resend_trigger   = join(",", concat([for key in sort(keys(terraform_data.xshield_applied_resources)) : terraform_data.xshield_applied_resources[key].id], terraform_data.xshield_applied_customer_rules[*].id))

  network_security_groups = local.network_security_group_ids
  subnet_associations     = { for key, association in azurerm_subnet_network_security_group_association.this : key => association.id if !contains(concat(keys(local.held_subnets), keys(local.contained_subnets)), key) }
  interface_associations  = { for key, association in azurerm_network_interface_security_group_association.this : key => association.id if !contains(concat(keys(local.held_interfaces), keys(local.contained_interfaces)), key) }
}

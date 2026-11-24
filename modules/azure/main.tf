# Applies the Azure resources Xshield rendered for one subscription and region. Every decision is in the snapshot: this
# module only creates what it lists, keyed as it lists it.

data "azurerm_client_config" "current" {}

locals {
  subscription_id = coalesce(var.cloud_account_id, data.azurerm_client_config.current.subscription_id)
  snap            = data.xshield_azure_enforcement_snapshot.this
  workspace       = coalesce(var.workspace, "xshield-enforcement-${local.subscription_id}-${var.region}")
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
  required_tags = { "ct:delivery" = "pipeline" }

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

# azurerm has no resource that leaves a group's other rules alone: a group's rules are given either inline or as rule
# resources, and using both on one group makes each overwrite the other's rules. So with enable_exclusive_rules off,
# the rules a group already holds that are not Xshield's are read back and given again with Xshield's. Xshield names
# its rules CT-Rule- or CT-Test-Rule-, as the cloud connector does, so a rule named otherwise is someone else's.
data "azurerm_resources" "network_security_groups" {
  count = var.enable_exclusive_rules || length(local.snap.network_security_groups) == 0 ? 0 : 1

  type = "Microsoft.Network/networkSecurityGroups"
}

locals {
  present_network_security_groups = { for group in try(data.azurerm_resources.network_security_groups[0].resources, []) : lower("${group.resource_group_name}/${group.name}") => true }
}

data "azurerm_network_security_group" "kept_rules" {
  for_each = { for key, group in local.snap.network_security_groups : key => group if lookup(local.present_network_security_groups, lower("${group.resource_group_name}/${group.name}"), false) }

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
  count = length(local.snap.interface_associations) + length(local.snap.held_interface_associations) + length(local.snap.released_interface_associations) > 0 ? 1 : 0

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
    local.snap.released_subnet_associations,
    { for key, held in local.snap.held_subnet_associations : key => held.level_id },
  )
}

# Xshield's groups are the ones tagged for a pipeline. Their names are no guide, as a name template can name them anything.
data "azurerm_resources" "xshield_network_security_groups" {
  count = length(local.leaving_interfaces) + length(local.leaving_subnets) > 0 ? 1 : 0

  type          = "Microsoft.Network/networkSecurityGroups"
  required_tags = { "ct:delivery" = "pipeline" }
}

locals {
  # A level that carries no group reads back as "" or null, which coalesce turns to "-": taking the association off it takes
  # nothing of yours.
  xshields_or_no_group = merge({ "-" = true }, { for group in try(data.azurerm_resources.xshield_network_security_groups[0].resources, []) : lower(group.id) => true })
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
      error_message = "Network interface ${self.name} now carries network security group ${element(split("/", coalesce(self.network_security_group_id, "-")), -1)} in place of Xshield's ${each.key}. Azure removes an association by clearing the interface's group, so removing Xshield's would take yours off it. Xshield holds the association once it next observes the subscription: plan again after that."
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
      error_message = "Subnet ${self.name} now carries network security group ${element(split("/", coalesce(self.network_security_group_id, "-")), -1)} in place of Xshield's ${each.key}. Azure removes an association by clearing the subnet's group, so removing Xshield's would take yours off it. Xshield holds the association once it next observes the subscription: plan again after that."
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
    if !lookup(local.xshields_or_no_group, lower(coalesce(try(data.azurerm_subnet.leaving[key].network_security_group_id, null), "-")), false)
  }
}

resource "azurerm_network_interface_security_group_association" "this" {
  for_each = merge(
    { for key, association in local.interface_associations : key => { level_id = association.network_interface_id, network_security_group_id = local.network_security_group_ids[association.network_security_group] } },
    local.held_interfaces,
  )

  network_interface_id      = each.value.level_id
  network_security_group_id = each.value.network_security_group_id
}

resource "azurerm_subnet_network_security_group_association" "this" {
  for_each = merge(
    { for key, association in local.snap.subnet_associations : key => { level_id = association.subnet_id, network_security_group_id = local.network_security_group_ids[association.network_security_group] } },
    local.held_subnets,
  )

  subnet_id                 = each.value.level_id
  network_security_group_id = each.value.network_security_group_id
}

# Xshield writes a workload's rules into a group of yours when every network interface or subnet of the workload carries
# one. azurerm takes a group's rules either inline or as rule resources, so each such group gets them as rule resources of
# this module's, except a group whose own configuration declares its rules inline: that configuration passes them through
# xshield_azure_security_rules, as its next apply would remove rules it does not declare.
locals {
  customer_network_security_groups_in_code = toset([for id in var.customer_network_security_groups_in_code : lower(id)])
  customer_network_security_groups         = { for key, group in local.snap.customer_network_security_groups : key => group if !contains(local.customer_network_security_groups_in_code, lower(group.id)) }
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
  subnet_associations     = { for key, association in azurerm_subnet_network_security_group_association.this : key => association.id if !contains(keys(local.held_subnets), key) }
  interface_associations  = { for key, association in azurerm_network_interface_security_group_association.this : key => association.id if !contains(keys(local.held_interfaces), key) }
}

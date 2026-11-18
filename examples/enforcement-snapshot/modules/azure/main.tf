# Applies the Azure resources Xshield rendered for one subscription and region. Every decision is in the snapshot: this
# module only creates what it lists, keyed as it lists it.

data "azurerm_client_config" "current" {}

locals {
  subscription_id = coalesce(var.cloud_account_id, data.azurerm_client_config.current.subscription_id)
  snap            = data.xshield_azure_enforcement_snapshot.this
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
  count = length(local.snap.interface_associations) > 0 ? 1 : 0

  type = "Microsoft.Network/networkInterfaces"
}

locals {
  present_interfaces     = { for interface in try(data.azurerm_resources.network_interfaces[0].resources, []) : lower(interface.id) => true }
  interface_associations = { for key, association in local.snap.interface_associations : key => association if lookup(local.present_interfaces, lower(association.network_interface_id), false) }
}

resource "azurerm_network_interface_security_group_association" "this" {
  for_each = local.interface_associations

  network_interface_id      = each.value.network_interface_id
  network_security_group_id = local.network_security_group_ids[each.value.network_security_group]
}

resource "azurerm_subnet_network_security_group_association" "this" {
  for_each = local.snap.subnet_associations

  subnet_id                 = each.value.subnet_id
  network_security_group_id = local.network_security_group_ids[each.value.network_security_group]
}

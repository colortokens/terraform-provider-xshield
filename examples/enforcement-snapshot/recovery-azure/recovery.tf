# Rebuilds a lost Azure enforcement state from the last receipt. Add this file to the enforcement workspace, set
# snapshot_version = data.xshield_azure_enforcement_status.recover.applied_version on the module, apply once, then
# delete this file and the pin. Delete handover.tf first if the workspace still has it: this file imports the
# associations it would, and two imports to one address fail the plan. An object deleted outside Terraform since stops
# the plan with "Cannot import non-existent remote object": add its key to skipped_imports, under its kind, and the
# apply creates it again.
data "azurerm_client_config" "recover" {}

data "xshield_azure_enforcement_status" "recover" {
  cloud_account_id = data.azurerm_client_config.recover.subscription_id
  region           = var.region
}

variable "skipped_imports" {
  type = object({
    network_security_groups = optional(set(string), [])
    interface_associations  = optional(set(string), [])
    subnet_associations     = optional(set(string), [])
    security_rules          = optional(set(string), [])
  })
  default  = {}
  nullable = false
}

locals {
  receipt = data.xshield_azure_enforcement_status.recover

  recovered_network_security_groups = { for key in setsubtract(keys(local.receipt.applied_network_security_groups), var.skipped_imports.network_security_groups) : key => local.receipt.applied_network_security_groups[key] }
  recovered_interface_associations = {
    for key, id in merge(
      { for key in setintersection(keys(local.receipt.applied_interface_associations), module.xshield_enforcement.interface_association_keys) : key => local.receipt.applied_interface_associations[key] },
      module.xshield_enforcement.kept_interface_association_imports,
    ) : key => id if !contains(var.skipped_imports.interface_associations, key)
  }
  recovered_subnet_associations = {
    for key, id in merge(
      { for key in setintersection(keys(local.receipt.applied_subnet_associations), module.xshield_enforcement.subnet_association_keys) : key => local.receipt.applied_subnet_associations[key] },
      module.xshield_enforcement.kept_subnet_association_imports,
    ) : key => id if !contains(var.skipped_imports.subnet_associations, key)
  }
  recovered_security_rules = { for key, id in module.xshield_enforcement.customer_security_rule_imports : key => id if !contains(var.skipped_imports.security_rules, key) }
}

import {
  for_each = local.recovered_network_security_groups
  to       = module.xshield_enforcement.azurerm_network_security_group.this[each.key]
  id       = each.value
}

import {
  for_each = local.recovered_interface_associations
  to       = module.xshield_enforcement.azurerm_network_interface_security_group_association.this[each.key]
  id       = each.value
}

import {
  for_each = local.recovered_subnet_associations
  to       = module.xshield_enforcement.azurerm_subnet_network_security_group_association.this[each.key]
  id       = each.value
}

import {
  for_each = local.recovered_security_rules
  to       = module.xshield_enforcement.azurerm_network_security_rule.customer[each.key]
  id       = each.value
}

import {
  to = module.xshield_enforcement.xshield_azure_enforcement_receipt.this[0]
  id = "${local.receipt.cloud_account_id}/${local.receipt.region}"
}

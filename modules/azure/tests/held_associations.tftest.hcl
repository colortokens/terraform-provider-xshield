# terraform test, offline: an earlier apply put Xshield's group ct-policy-0123456789ab on nic-old and ct-policy-ffffffffffff
# on snet-old, and this version no longer wants either. Azure removes an association by clearing its level's group, so
# what each level carries now decides whether the apply removes it.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_resources" {
    defaults = {
      resources = [{
        id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old"
        name                = "nic-old"
        type                = "Microsoft.Network/networkInterfaces"
        location            = "eastus2"
        resource_group_name = "rg-app"
        tags                = {}
      }]
    }
  }
}

mock_provider "xshield" {
  mock_data "xshield_azure_enforcement_snapshot" {
    defaults = {
      published                        = true
      version                          = "v43"
      network_security_groups          = {}
      interface_associations           = {}
      subnet_associations              = {}
      assets                           = {}
      held_interface_associations      = {}
      held_subnet_associations         = {}
      released_interface_associations  = {}
      released_subnet_associations     = {}
      customer_network_security_groups = {}
    }
  }
}

variables {
  region = "eastus2"
}

run "a_released_association_whose_interface_still_carries_xshields_group_is_removed" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published                       = true
      version                         = "v43"
      released_interface_associations = { "ct-policy-0123456789ab" = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old" }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-0123456789ab"]
    values = { name = "nic-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab" }
  }
  override_data {
    target = data.azurerm_resources.xshield_network_security_groups[0]
    values = { resources = [{
      id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
      name                = "ct-policy-0123456789ab"
      type                = "Microsoft.Network/networkSecurityGroups"
      location            = "eastus2"
      resource_group_name = "rg-app"
      tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
    }] }
  }

  assert {
    condition     = keys(data.azurerm_network_interface.leaving) == ["ct-policy-0123456789ab"]
    error_message = "The interface of a released association must be read before its removal is planned."
  }
  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A released association whose interface carries Xshield's group must leave the configuration."
  }
}

# With a name template Xshield's group is named sg-prod-0123456789ab, not by its key, and its pipeline tag says it is Xshield's.
run "a_released_association_whose_interface_carries_xshields_group_under_a_template_name_is_removed" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published                       = true
      version                         = "v43"
      released_interface_associations = { "ct-policy-0123456789ab" = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old" }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-0123456789ab"]
    values = { name = "nic-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/SG-Prod-0123456789ab" }
  }
  override_data {
    target = data.azurerm_resources.xshield_network_security_groups[0]
    values = { resources = [{
      id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/sg-prod-0123456789ab"
      name                = "sg-prod-0123456789ab"
      type                = "Microsoft.Network/networkSecurityGroups"
      location            = "eastus2"
      resource_group_name = "rg-app"
      tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
    }] }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A released association whose interface carries Xshield's group must leave the configuration, whatever the group is named and however Azure cases its ID."
  }
}

run "a_held_subnet_association_whose_subnet_carries_xshields_group_under_a_template_name_is_removed" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      held_subnet_associations = { "ct-policy-ffffffffffff" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/sg-prod-ffffffffffff"
      } }
    }
  }
  override_data {
    target = data.azurerm_subnet.leaving["ct-policy-ffffffffffff"]
    values = { name = "snet-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/sg-prod-ffffffffffff" }
  }
  override_data {
    target = data.azurerm_resources.xshield_network_security_groups[0]
    values = { resources = [{
      id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/sg-prod-ffffffffffff"
      name                = "sg-prod-ffffffffffff"
      type                = "Microsoft.Network/networkSecurityGroups"
      location            = "eastus2"
      resource_group_name = "rg-net"
      tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
    }] }
  }

  assert {
    condition     = length(azurerm_subnet_network_security_group_association.this) == 0
    error_message = "A held association whose subnet carries Xshield's own group again is no longer held, whatever the group is named."
  }
}

run "a_released_association_whose_interface_carries_no_group_is_removed" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published                       = true
      version                         = "v43"
      released_interface_associations = { "ct-policy-0123456789ab" = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old" }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-0123456789ab"]
    values = { name = "nic-old", network_security_group_id = "" }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A released association whose interface carries no group must leave the configuration."
  }
}

run "a_released_association_whose_interface_now_carries_your_group_fails_the_plan" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published                       = true
      version                         = "v43"
      released_interface_associations = { "ct-policy-0123456789ab" = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old" }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-0123456789ab"]
    values = { name = "nic-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/yours" }
  }

  expect_failures = [data.azurerm_network_interface.leaving]
}

run "a_released_subnet_association_whose_subnet_now_carries_your_group_fails_the_plan" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published                    = true
      version                      = "v43"
      released_subnet_associations = { "ct-policy-ffffffffffff" = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old" }
    }
  }
  override_data {
    target = data.azurerm_subnet.leaving["ct-policy-ffffffffffff"]
    values = { name = "snet-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/yours" }
  }

  expect_failures = [data.azurerm_subnet.leaving]
}

run "a_held_association_stays_as_applied_and_is_left_out_of_the_receipt" {
  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      held_interface_associations = { "ct-policy-0123456789ab" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
      } }
      held_subnet_associations = { "ct-policy-ffffffffffff" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-ffffffffffff"
      } }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-0123456789ab"]
    values = { name = "nic-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/yours" }
  }
  override_data {
    target = data.azurerm_subnet.leaving["ct-policy-ffffffffffff"]
    values = { name = "snet-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/yours" }
  }

  assert {
    condition     = azurerm_network_interface_security_group_association.this["ct-policy-0123456789ab"].network_security_group_id == "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
    error_message = "A held interface association must stay with the group ID the earlier apply associated, so the plan changes nothing on the interface."
  }
  assert {
    condition     = azurerm_subnet_network_security_group_association.this["ct-policy-ffffffffffff"].subnet_id == "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old"
    error_message = "A held subnet association must stay on its subnet."
  }
  assert {
    condition     = azurerm_subnet_network_security_group_association.this["ct-policy-ffffffffffff"].network_security_group_id == "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/yours"
    error_message = "A held subnet association must name the group the subnet carries now, as azurerm reads it back, so the plan does not replace it and clear that group."
  }
  assert {
    condition     = length(xshield_azure_enforcement_receipt.this[0].interface_associations) == 0 && length(xshield_azure_enforcement_receipt.this[0].subnet_associations) == 0
    error_message = "The receipt must name only the associations this version wants, never a held one."
  }
}

run "a_held_association_whose_level_now_carries_no_group_is_removed" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      held_interface_associations = { "ct-policy-0123456789ab" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
      } }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-0123456789ab"]
    values = { name = "nic-old", network_security_group_id = "" }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A held association whose interface carries no group must leave the configuration, which removes nothing of yours."
  }
}

run "a_held_association_whose_interface_is_deleted_is_dropped_without_a_read" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      held_interface_associations = { "ct-policy-0123456789ab" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-gone"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
      } }
    }
  }

  assert {
    condition     = length(data.azurerm_network_interface.leaving) == 0 && length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A held association on a deleted interface must be neither read nor kept."
  }
}

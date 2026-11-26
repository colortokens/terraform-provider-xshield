# terraform test, offline: Xshield's cloud connector contains the workloads behind Xshield's group ct-policy-0123456789ab on
# nic-old and ct-policy-ffffffffffff on snet-old, by putting a group of its own on each level in place of Xshield's. The apply
# keeps each association as its state holds it, so it never takes the connector's group off.

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
  mock_data "azurerm_virtual_network" {
    defaults = { subnets = ["snet-app", "snet-old", "snet-db"] }
  }
}

# Every subnet the snapshots below name exists, in a virtual network Azure lists.
override_data {
  target = data.azurerm_resources.virtual_networks
  values = {
    resources = [
      {
        id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a"
        name                = "vnet-a"
        type                = "Microsoft.Network/virtualNetworks"
        location            = "eastus2"
        resource_group_name = "rg-net"
        tags                = {}
      },
      {
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a"
        name                = "vnet-a"
        type                = "Microsoft.Network/virtualNetworks"
        location            = "eastus2"
        resource_group_name = "rg-net"
        tags                = {}
      },
      {
        id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-b"
        name                = "vnet-b"
        type                = "Microsoft.Network/virtualNetworks"
        location            = "eastus2"
        resource_group_name = "rg-net"
        tags                = {}
      },
    ]
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
      contained_interface_associations = {}
      contained_subnet_associations    = {}
      customer_network_security_groups = {}
    }
  }
}

variables {
  region = "eastus2"
}

run "a_contained_association_stays_as_applied_and_is_left_out_of_the_receipt" {
  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      contained_interface_associations = { "ct-policy-0123456789ab" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
      } }
      contained_subnet_associations = { "ct-policy-ffffffffffff" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-ffffffffffff"
      } }
    }
  }
  override_data {
    target = data.azurerm_subnet.contained["ct-policy-ffffffffffff"]
    values = { name = "snet-old", network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/CT-managed-nsg-4d5e6f" }
  }

  assert {
    condition     = azurerm_network_interface_security_group_association.this["ct-policy-0123456789ab"].network_security_group_id == "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
    error_message = "A contained interface association must stay with the group ID the earlier apply associated, so the plan changes nothing on the interface."
  }
  assert {
    condition     = azurerm_subnet_network_security_group_association.this["ct-policy-ffffffffffff"].network_security_group_id == "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/CT-managed-nsg-4d5e6f"
    error_message = "A contained subnet association must name the group the subnet carries now, as azurerm reads it back, so the plan does not replace it and clear the connector's group."
  }
  assert {
    condition     = length(xshield_azure_enforcement_receipt.this[0].interface_associations) == 0 && length(xshield_azure_enforcement_receipt.this[0].subnet_associations) == 0
    error_message = "The receipt must leave a contained association out."
  }
}

run "a_contained_subnet_association_whose_subnet_carries_xshields_group_keeps_it" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      contained_subnet_associations = { "ct-policy-ffffffffffff" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-ffffffffffff"
      } }
    }
  }
  override_data {
    target = data.azurerm_subnet.contained["ct-policy-ffffffffffff"]
    values = { name = "snet-old", network_security_group_id = "" }
  }

  assert {
    condition     = azurerm_subnet_network_security_group_association.this["ct-policy-ffffffffffff"].network_security_group_id == "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-ffffffffffff"
    error_message = "A contained subnet association reads back as the group the apply associated when the subnet shows none."
  }
}

run "a_contained_association_on_a_deleted_interface_is_dropped" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      contained_interface_associations = { "ct-policy-0123456789ab" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-gone"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0123456789ab"
      } }
    }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A contained association whose interface went with its workload must not be planned."
  }
}

run "a_contained_association_on_a_deleted_subnet_is_dropped_without_a_read" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v43"
      contained_subnet_associations = { "ct-policy-ffffffffffff" = {
        level_id                  = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-old"
        network_security_group_id = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-managed-nsg-snet-old"
      } }
    }
  }
  override_data {
    target = data.azurerm_resources.virtual_networks
    values = { resources = [] }
  }

  assert {
    condition     = length(data.azurerm_subnet.contained) == 0 && length(azurerm_subnet_network_security_group_association.this) == 0
    error_message = "A contained association whose subnet went with its virtual network must not be read or planned."
  }
}

# terraform test, offline: the cloud connector enforced at nic-app and snet-app with groups of its own while each had
# none, so this version lists their associations as handover associations. What each level carries now decides whether
# the apply takes its association over, and how.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_resources" {
    defaults = {
      resources = [{
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-app"
        name                = "nic-app"
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
      published = true
      version   = "v44"
      network_security_groups = {
        "ct-policy-aaaaaaaaaaaa" = {
          name                = "sg-prod-aaaaaaaaaaaa"
          resource_group_name = "rg-app"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
          security_rules      = []
        }
        "ct-policy-bbbbbbbbbbbb" = {
          name                = "ct-policy-bbbbbbbbbbbb"
          resource_group_name = "rg-net"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "subnet" }
          security_rules      = []
        }
      }
      interface_associations = {}
      subnet_associations    = {}
      handover_interface_associations = {
        "ct-policy-aaaaaaaaaaaa" = {
          network_security_group = "ct-policy-aaaaaaaaaaaa"
          network_interface_id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-app"
        }
      }
      handover_subnet_associations = {
        "ct-policy-bbbbbbbbbbbb" = {
          network_security_group = "ct-policy-bbbbbbbbbbbb"
          subnet_id              = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app"
        }
      }
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

run "a_level_that_still_carries_the_connectors_group_is_left_alone" {
  command = plan

  override_data {
    target = data.azurerm_network_interface.handover["ct-policy-aaaaaaaaaaaa"]
    values = { name = "nic-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/CT-nic-app-nsg" }
  }
  override_data {
    target = data.azurerm_subnet.handover["ct-policy-bbbbbbbbbbbb"]
    values = { name = "snet-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/CT-snet-app-nsg" }
  }

  expect_failures = [check.xshield_handover]

  assert {
    condition     = length(azurerm_network_security_group.this) == 2
    error_message = "The groups must be created while the connector's groups are still on their levels, so the connector can put them in place."
  }
  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0 && length(azurerm_subnet_network_security_group_association.this) == 0
    error_message = "An association on a level that carries the connector's group would clear that group until the apply ends."
  }
  assert {
    condition     = output.handover_interface_association_imports == {} && output.handover_subnet_association_imports == {}
    error_message = "Nothing is imported while the connector's group is on the level."
  }
}

run "a_level_the_connector_has_handed_over_is_imported" {
  command = plan

  override_data {
    target = data.azurerm_network_interface.handover["ct-policy-aaaaaaaaaaaa"]
    values = { name = "nic-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/RG-APP/providers/Microsoft.Network/networkSecurityGroups/sg-prod-aaaaaaaaaaaa" }
  }
  override_data {
    target = data.azurerm_subnet.handover["ct-policy-bbbbbbbbbbbb"]
    values = { name = "snet-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb" }
  }

  assert {
    condition     = keys(azurerm_network_interface_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"] && keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-bbbbbbbbbbbb"]
    error_message = "A level that carries Xshield's group, however Azure cases its ID, must have its association taken over."
  }
  assert {
    condition = output.handover_interface_association_imports == {
      "ct-policy-aaaaaaaaaaaa" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-app|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/RG-APP/providers/Microsoft.Network/networkSecurityGroups/sg-prod-aaaaaaaaaaaa"
    }
    error_message = "A network interface association's import ID is the interface's ID and the ID of the group it carries, as Azure gives it."
  }
  assert {
    condition = output.handover_subnet_association_imports == {
      "ct-policy-bbbbbbbbbbbb" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app"
    }
    error_message = "A subnet association's import ID is the subnet's ID."
  }
}

run "a_level_that_carries_no_group_has_its_association_created" {
  command = plan

  override_data {
    target = data.azurerm_network_interface.handover["ct-policy-aaaaaaaaaaaa"]
    values = { name = "nic-app", network_security_group_id = "" }
  }
  override_data {
    target = data.azurerm_subnet.handover["ct-policy-bbbbbbbbbbbb"]
    values = { name = "snet-app", network_security_group_id = null }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 1 && length(azurerm_subnet_network_security_group_association.this) == 1
    error_message = "A level that carries no group takes its association like any other, as there is nothing of the connector's to clear."
  }
  assert {
    condition     = output.handover_interface_association_imports == {} && output.handover_subnet_association_imports == {}
    error_message = "There is no association to import on a level that carries no group."
  }
}

run "a_level_that_carries_a_group_of_yours_is_left_alone" {
  command = plan

  override_data {
    target = data.azurerm_network_interface.handover["ct-policy-aaaaaaaaaaaa"]
    values = { name = "nic-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/app-team-nsg" }
  }
  override_data {
    target = data.azurerm_subnet.handover["ct-policy-bbbbbbbbbbbb"]
    values = { name = "snet-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb" }
  }

  expect_failures = [check.xshield_handover]

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0 && output.handover_interface_association_imports == {}
    error_message = "Creating or importing an association on a level that carries another group would take that group off it."
  }
  assert {
    condition     = keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-bbbbbbbbbbbb"]
    error_message = "A level handed over is taken over whatever another level still carries."
  }
}

run "an_interface_that_no_longer_exists_is_not_read" {
  command = plan

  override_data {
    target = data.azurerm_resources.network_interfaces[0]
    values = { resources = [] }
  }
  override_data {
    target = data.azurerm_subnet.handover["ct-policy-bbbbbbbbbbbb"]
    values = { name = "snet-app", network_security_group_id = null }
  }

  assert {
    condition     = length(data.azurerm_network_interface.handover) == 0 && length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "A deleted network interface must not fail the plan."
  }
}

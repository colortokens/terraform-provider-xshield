# terraform test, offline: both providers are mocked. A resource group holds one network security group per name, so the
# name of each group the last receipt does not hold is looked up, and a group of yours already holding it stops the plan
# before azurerm refuses the group and suggests importing yours.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_resources" {
    defaults = { resources = [] }
  }
}

mock_provider "xshield" {
  mock_data "xshield_azure_enforcement_status" {
    defaults = {
      applied_network_security_groups = {}
      applied_interface_associations  = {}
      applied_subnet_associations     = {}
    }
  }
  mock_data "xshield_azure_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v42"
      network_security_groups = {
        "ct-policy-d2dd5b7ea0d5" = {
          name                = "xs-vm-web-d2dd5b7ea0d5"
          resource_group_name = "rg-app"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
          security_rules      = []
        }
      }
      interface_associations = {}
      subnet_associations    = {}
      assets = {
        "web" = { level = "networkInterface", network_security_groups = ["ct-policy-d2dd5b7ea0d5"] }
      }
      customer_network_security_groups = {}
    }
  }
}

variables {
  region = "eastus2"
}

run "a_group_of_yours_holding_a_new_groups_name_stops_the_plan" {
  command = plan

  override_data {
    target = data.azurerm_resources.network_security_groups
    values = {
      resources = [{
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/RG-APP/providers/Microsoft.Network/networkSecurityGroups/XS-VM-WEB-D2DD5B7EA0D5"
        name                = "XS-VM-WEB-D2DD5B7EA0D5"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "westus2"
        resource_group_name = "RG-APP"
        tags                = { "owner" = "app-team" }
      }]
    }
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "xshields_group_holding_the_name_is_no_holder" {
  command = plan

  override_data {
    target = data.azurerm_resources.network_security_groups
    values = {
      resources = [{
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/xs-vm-web-d2dd5b7ea0d5"
        name                = "xs-vm-web-d2dd5b7ea0d5"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "eastus2"
        resource_group_name = "rg-app"
        tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
      }]
    }
  }

  assert {
    condition     = length(local.network_security_group_name_holders) == 0
    error_message = "a group carrying Xshield's ct:delivery tag, which an apply created before it failed without a receipt, held up the plan"
  }
}

run "a_group_of_yours_in_another_resource_group_is_no_holder" {
  command = plan

  override_data {
    target = data.azurerm_resources.network_security_groups
    values = {
      resources = [{
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-other/providers/Microsoft.Network/networkSecurityGroups/xs-vm-web-d2dd5b7ea0d5"
        name                = "xs-vm-web-d2dd5b7ea0d5"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "eastus2"
        resource_group_name = "rg-other"
        tags                = {}
      }]
    }
  }

  assert {
    condition     = length(local.network_security_group_name_holders) == 0
    error_message = "a group in another resource group held up the plan"
  }
}

run "a_group_the_last_receipt_holds_is_not_looked_up" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_status.this
    values = {
      applied_network_security_groups = {
        "ct-policy-d2dd5b7ea0d5" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/xs-vm-web-d2dd5b7ea0d5"
      }
      applied_interface_associations = {}
      applied_subnet_associations    = {}
    }
  }
  override_data {
    target = data.azurerm_resources.network_security_groups
    values = {
      resources = [{
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/xs-vm-web-d2dd5b7ea0d5"
        name                = "xs-vm-web-d2dd5b7ea0d5"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "eastus2"
        resource_group_name = "rg-app"
        tags                = {}
      }]
    }
  }

  assert {
    condition     = length(data.azurerm_resources.network_security_groups) == 0
    error_message = "with exclusive rules and every group applied, the module listed the subscription's groups"
  }
}

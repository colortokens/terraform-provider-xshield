# terraform test, offline: both providers are mocked. handover.tf is a file for the enforcement workspace, so it is
# tested in one: copy ../enforcement-azure/main.tf, handover.tf and this tests directory into an empty directory beside
# handover-azure/, and run terraform init and terraform test there.

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
  subscription_id = "11111111-2222-3333-4444-555555555555"
  region          = "eastus2"
}

# A mock provider cannot import, so the import itself is not run here.
run "a_level_that_carries_no_group_imports_nothing" {
  command = plan

  override_data {
    target = module.xshield_enforcement.data.azurerm_network_interface.handover["ct-policy-aaaaaaaaaaaa"]
    values = { name = "nic-app", network_security_group_id = "" }
  }
  override_data {
    target = module.xshield_enforcement.data.azurerm_subnet.handover["ct-policy-bbbbbbbbbbbb"]
    values = { name = "snet-app", network_security_group_id = null }
  }

  assert {
    condition     = module.xshield_enforcement.handover_interface_association_imports == {} && module.xshield_enforcement.handover_subnet_association_imports == {}
    error_message = "There is nothing to import on a level that carries no group."
  }
}

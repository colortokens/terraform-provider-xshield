# terraform test, offline: each plan below runs against the state an earlier run applied, with Azure changed since. web's
# group first goes on its network interface, then moves to its subnet; then the subnet's group changes under the
# association; then a group of yours that holds Xshield's rules is deleted.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_subnet" {
    defaults = { network_security_group_id = "" }
  }
  mock_data "azurerm_virtual_network" {
    defaults = { subnets = ["snet-app"] }
  }
  mock_data "azurerm_network_security_group" {
    defaults = { security_rule = [] }
  }
}

override_data {
  target = data.azurerm_resources.virtual_networks
  values = { resources = [{
    id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a"
    name                = "vnet-a"
    type                = "Microsoft.Network/virtualNetworks"
    location            = "eastus2"
    resource_group_name = "rg-net"
    tags                = {}
  }] }
}

override_data {
  target = data.azurerm_resources.network_interfaces
  values = { resources = [{
    id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web"
    name                = "nic-web"
    type                = "Microsoft.Network/networkInterfaces"
    location            = "eastus2"
    resource_group_name = "rg-app"
    tags                = {}
  }] }
}

override_data {
  target = data.azurerm_resources.xshield_network_security_groups
  values = { resources = [
    {
      id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa"
      name                = "ct-policy-aaaaaaaaaaaa"
      type                = "Microsoft.Network/networkSecurityGroups"
      location            = "eastus2"
      resource_group_name = "rg-net"
      tags                = { "ct:delivery" = "pipeline" }
    },
    {
      id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb"
      name                = "ct-policy-bbbbbbbbbbbb"
      type                = "Microsoft.Network/networkSecurityGroups"
      location            = "eastus2"
      resource_group_name = "rg-net"
      tags                = { "ct:delivery" = "pipeline" }
    },
  ] }
}

override_resource {
  target = azurerm_network_security_group.this["ct-policy-aaaaaaaaaaaa"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa" }
}

mock_provider "xshield" {
  mock_data "xshield_azure_enforcement_snapshot" {
    defaults = {
      published = true
      version   = "v2"
      network_security_groups = {
        "ct-policy-aaaaaaaaaaaa" = {
          name                = "ct-policy-aaaaaaaaaaaa"
          resource_group_name = "rg-net"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "subnet" }
          security_rules      = []
        }
      }
      interface_associations = {}
      subnet_associations = {
        "ct-policy-aaaaaaaaaaaa" = {
          network_security_group = "ct-policy-aaaaaaaaaaaa"
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
  mock_data "xshield_azure_security_rules" {
    defaults = {
      published = true
      xshield_security_rules = [
        { name = "CT-Rule-Allow-64c02cd7face", description = "", priority = 100, direction = "Inbound", access = "Allow", protocol = "*", source_address_prefix = "AzureLoadBalancer", source_address_prefixes = [], source_application_security_group_ids = [], destination_address_prefix = "10.1.0.4/32", destination_address_prefixes = [], destination_application_security_group_ids = [], source_port_range = "*", source_port_ranges = [], destination_port_range = "*", destination_port_ranges = [] },
      ]
      security_rules = []
    }
  }
}

variables {
  region = "eastus2"
}

run "web_is_enforced_on_its_network_interface" {
  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v1"
      network_security_groups = {
        "ct-policy-aaaaaaaaaaaa" = {
          name                = "ct-policy-aaaaaaaaaaaa"
          resource_group_name = "rg-net"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
          security_rules      = []
        }
      }
      interface_associations = {
        "ct-policy-aaaaaaaaaaaa" = {
          network_security_group = "ct-policy-aaaaaaaaaaaa"
          network_interface_id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web"
        }
      }
      subnet_associations = {}
    }
  }

  assert {
    condition     = keys(azurerm_network_interface_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"] && length(azurerm_subnet_network_security_group_association.this) == 0
    error_message = "v1 puts web's group on its network interface only."
  }
}

run "moving_web_from_its_network_interface_to_its_subnet_plans_both_changes" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "v2"
      network_security_groups = {
        "ct-policy-aaaaaaaaaaaa" = {
          name                = "ct-policy-aaaaaaaaaaaa"
          resource_group_name = "rg-net"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "subnet" }
          security_rules      = []
        }
      }
      subnet_associations = {
        "ct-policy-aaaaaaaaaaaa" = {
          network_security_group = "ct-policy-aaaaaaaaaaaa"
          subnet_id              = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app"
        }
      }
      released_interface_associations = { "ct-policy-aaaaaaaaaaaa" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web" }
    }
  }
  override_data {
    target = data.azurerm_network_interface.leaving["ct-policy-aaaaaaaaaaaa"]
    values = { name = "nic-web", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa" }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "The association on web's network interface, which carries Xshield's group, must leave the configuration."
  }
  assert {
    condition     = keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"]
    error_message = "web's group must go on its subnet."
  }
}

run "web_is_enforced_on_its_subnet" {
  assert {
    condition     = keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"] && length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "v2 puts web's group on its subnet only."
  }
}

run "a_group_of_yours_put_on_the_subnet_since_stops_the_plan" {
  command = plan

  override_data {
    target = data.azurerm_subnet.associated["ct-policy-aaaaaaaaaaaa"]
    values = { name = "snet-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-yours" }
  }

  expect_failures = [data.azurerm_subnet.associated]
}

run "the_subnet_carrying_the_group_the_association_wants_plans" {
  command = plan

  override_data {
    target = data.azurerm_subnet.associated["ct-policy-aaaaaaaaaaaa"]
    values = { name = "snet-app", network_security_group_id = "/SUBSCRIPTIONS/11111111-2222-3333-4444-555555555555/resourceGroups/RG-NET/providers/Microsoft.Network/networkSecurityGroups/CT-POLICY-AAAAAAAAAAAA" }
  }

  assert {
    condition     = keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"]
    error_message = "A subnet carrying the association's own group, whatever the case of its ID, must keep the association."
  }
}

run "the_subnet_carrying_another_group_of_xshields_plans" {
  command = plan

  override_data {
    target = data.azurerm_subnet.associated["ct-policy-aaaaaaaaaaaa"]
    values = { name = "snet-app", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb" }
  }

  assert {
    condition     = keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"]
    error_message = "A subnet carrying a group tagged for a pipeline holds nothing of yours, so the association is planned."
  }
}

run "a_bare_subnet_plans" {
  command = plan

  assert {
    condition     = keys(azurerm_subnet_network_security_group_association.this) == ["ct-policy-aaaaaaaaaaaa"]
    error_message = "A subnet that carries no group holds nothing of yours, so the association is planned."
  }
}

run "xshields_rules_go_into_a_group_of_yours" {
  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published               = true
      version                 = "v3"
      network_security_groups = {}
      subnet_associations     = {}
      customer_network_security_groups = {
        "customer-nsg-5b8ff476f40c" = {
          id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-yours"
          resource_group_name = "rg-net"
          name                = "nsg-yours"
          security_rules      = []
          subnets             = {}
        }
      }
    }
  }
  override_data {
    target = data.azurerm_resources.customer_network_security_groups
    values = { resources = [{
      id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-yours"
      name                = "nsg-yours"
      type                = "Microsoft.Network/networkSecurityGroups"
      location            = "eastus2"
      resource_group_name = "rg-net"
      tags                = {}
    }] }
  }

  assert {
    condition     = keys(azurerm_network_security_rule.customer) == ["customer-nsg-5b8ff476f40c/CT-Rule-Allow-64c02cd7face"]
    error_message = "Xshield's rule must go into your group."
  }
}

run "a_group_of_yours_deleted_since_plans_the_removal_of_its_rules_without_reading_it" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published               = true
      version                 = "v3"
      network_security_groups = {}
      subnet_associations     = {}
      customer_network_security_groups = {
        "customer-nsg-5b8ff476f40c" = {
          id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-yours"
          resource_group_name = "rg-net"
          name                = "nsg-yours"
          security_rules      = []
          subnets             = {}
        }
      }
    }
  }
  override_data {
    target = data.azurerm_resources.customer_network_security_groups
    values = { resources = [] }
  }

  assert {
    condition     = length(data.azurerm_network_security_group.customer) == 0 && length(azurerm_network_security_rule.customer) == 0
    error_message = "A group of yours deleted before Xshield observes it must not be read, which fails the plan, and its rules must leave the configuration."
  }
}

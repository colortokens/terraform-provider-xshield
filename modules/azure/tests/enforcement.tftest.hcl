# terraform test, offline: both providers are mocked, and the snapshot below is shaped as the xshield provider returns
# what Xshield serves: web enforced on its network interface, api on its subnet, and db refused.

mock_provider "azurerm" {
  mock_data "azurerm_subnet" {
    defaults = { network_security_group_id = "" }
  }
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_resources" {
    defaults = { resources = [] }
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
      published = true
      version   = "v42"
      network_security_groups = {
        "ct-policy-d2dd5b7ea0d5" = {
          name                = "ct-policy-d2dd5b7ea0d5"
          resource_group_name = "rg-app"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
          security_rules = [
            {
              name                         = "CT-Rule-Allow-AzureLoadBalancer"
              priority                     = 100
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "*"
              source_address_prefix        = "AzureLoadBalancer"
              source_address_prefixes      = []
              destination_address_prefix   = "*"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "*"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Allow-faf81b0d4310"
              priority                     = 501
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "Tcp"
              source_address_prefix        = ""
              source_address_prefixes      = ["10.20.0.0/16", "10.21.0.0/16"]
              destination_address_prefix   = "10.1.0.4/32"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "443"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Allow-096c9d78174c"
              priority                     = 501
              direction                    = "Outbound"
              access                       = "Allow"
              protocol                     = "Tcp"
              source_address_prefix        = "10.1.0.4/32"
              source_address_prefixes      = []
              destination_address_prefix   = "Storage.EastUS2"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "443"
              destination_port_ranges      = []
            },
          ]
        }
        "ct-policy-8d612d812776" = {
          name                = "ct-policy-8d612d812776"
          resource_group_name = "rg-net"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "subnet" }
          security_rules = [
            {
              name                         = "CT-Rule-Allow-049ab4a026fc"
              priority                     = 501
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "Tcp"
              source_address_prefix        = "10.0.0.0/8"
              source_address_prefixes      = []
              destination_address_prefix   = "10.1.0.5/32"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "8000-8080"
              destination_port_ranges      = []
            },
          ]
        }
      }
      interface_associations = {
        "ct-policy-d2dd5b7ea0d5" = {
          network_security_group = "ct-policy-d2dd5b7ea0d5"
          network_interface_id   = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web"
        }
      }
      subnet_associations = {
        "ct-policy-8d612d812776" = {
          network_security_group = "ct-policy-8d612d812776"
          subnet_id              = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app"
        }
      }
      assets = {
        "web" = { level = "networkInterface", network_security_groups = ["ct-policy-d2dd5b7ea0d5"] }
        "api" = { level = "subnet", network_security_groups = ["ct-policy-8d612d812776"] }
        "db"  = { level = null, network_security_groups = [] }
      }
      customer_network_security_groups = {}
    }
  }
}

variables {
  region = "eastus2"
  tags   = { "cost-center" = "platform-security" }
}

# azurerm checks the form of a group's ID wherever it is passed, so each mocked group gets one of Azure's.
override_resource {
  target = azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-d2dd5b7ea0d5" }
}

override_resource {
  target = azurerm_network_security_group.this["ct-policy-8d612d812776"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-8d612d812776" }
}

# Azure lists resource IDs in whatever case it stored them, so the interface is found whatever the case.
override_data {
  target = data.azurerm_resources.network_interfaces
  values = {
    resources = [{
      id                  = "/SUBSCRIPTIONS/sub-a/resourcegroups/RG-APP/providers/microsoft.network/networkinterfaces/nic-web"
      name                = "nic-web"
      type                = "Microsoft.Network/networkInterfaces"
      location            = "eastus2"
      resource_group_name = "rg-app"
      tags                = {}
    }]
  }
}

run "each_group_holds_its_whole_rule_set_as_azure_reads_it_back" {
  assert {
    condition     = length(azurerm_network_security_group.this) == 2
    error_message = "One network security group per network interface or subnet is expected."
  }
  assert {
    condition = (azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].name == "ct-policy-d2dd5b7ea0d5" &&
      azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].resource_group_name == "rg-app" &&
    azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].location == "eastus2")
    error_message = "The group must take its name, resource group and region from the snapshot."
  }
  assert {
    condition     = azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].tags == tomap({ "ct:delivery" = "pipeline", "ct:level" = "networkInterface", "cost-center" = "platform-security" })
    error_message = "The group must carry Xshield's tags and the module's."
  }
  assert {
    condition     = length(azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule) == 3 && length(azurerm_network_security_group.this["ct-policy-8d612d812776"].security_rule) == 1
    error_message = "Each group must hold exactly the rules the snapshot lists for it."
  }
  assert {
    condition = alltrue([for rule in azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule : (
      rule.description == "" && length(rule.source_application_security_group_ids) == 0 && length(rule.destination_application_security_group_ids) == 0
    )])
    error_message = "The fields Xshield never sets must be what Azure reads back, or every plan shows a change."
  }
  assert {
    condition = anytrue([for rule in azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule : (
      rule.name == "CT-Rule-Allow-faf81b0d4310" && rule.priority == 501 && rule.direction == "Inbound" && rule.access == "Allow" && rule.protocol == "Tcp" &&
      rule.source_address_prefix == "" && rule.source_address_prefixes == toset(["10.20.0.0/16", "10.21.0.0/16"]) &&
      rule.destination_address_prefix == "10.1.0.4/32" && length(rule.destination_address_prefixes) == 0 &&
      rule.source_port_range == "*" && rule.destination_port_range == "443"
    )])
    error_message = "A rule must pass to Azure as the snapshot gives it."
  }
  assert {
    condition = anytrue([for rule in azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule : (
      rule.name == "CT-Rule-Allow-096c9d78174c" && rule.destination_address_prefix == "Storage.EastUS2"
    )])
    error_message = "A service tag must stay in the singular field, the only one Azure takes it in."
  }
}

run "each_group_goes_on_its_network_interface_or_subnet" {
  assert {
    condition = (azurerm_network_interface_security_group_association.this["ct-policy-d2dd5b7ea0d5"].network_interface_id == "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web" &&
    azurerm_network_interface_security_group_association.this["ct-policy-d2dd5b7ea0d5"].network_security_group_id == azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].id)
    error_message = "web's group must go on web's network interface."
  }
  assert {
    condition = (azurerm_subnet_network_security_group_association.this["ct-policy-8d612d812776"].subnet_id == "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app" &&
    azurerm_subnet_network_security_group_association.this["ct-policy-8d612d812776"].network_security_group_id == azurerm_network_security_group.this["ct-policy-8d612d812776"].id)
    error_message = "api's group must go on api's subnet."
  }
  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 1 && length(azurerm_subnet_network_security_group_association.this) == 1
    error_message = "Only the snapshot's associations are expected."
  }
  assert {
    condition = (output.network_security_group_ids["web"] == [azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].id] &&
    output.network_security_group_ids["db"] == [])
    error_message = "Each asset must map to its own groups' IDs, and a refused one to none."
  }
  assert {
    condition     = output.summary.network_security_groups == 2 && output.summary.security_rules == 4 && output.summary.interface_associations == 1 && output.summary.subnet_associations == 1
    error_message = "The summary must count what the version holds."
  }
  assert {
    condition = (xshield_azure_enforcement_receipt.this[0].snapshot_version == "v42" &&
      xshield_azure_enforcement_receipt.this[0].workspace == "xshield-enforcement-11111111-2222-3333-4444-555555555555-eastus2" &&
      xshield_azure_enforcement_receipt.this[0].exclusive_rules &&
      xshield_azure_enforcement_receipt.this[0].network_security_groups == tomap({ for key, group in azurerm_network_security_group.this : key => group.id }) &&
      xshield_azure_enforcement_receipt.this[0].subnet_associations == tomap({ "ct-policy-8d612d812776" = azurerm_subnet_network_security_group_association.this["ct-policy-8d612d812776"].id }) &&
    xshield_azure_enforcement_receipt.this[0].interface_associations == tomap({ "ct-policy-d2dd5b7ea0d5" = azurerm_network_interface_security_group_association.this["ct-policy-d2dd5b7ea0d5"].id }))
    error_message = "The receipt must name the applied version, and the ID of every group and association created, by its key."
  }
  assert {
    condition = xshield_azure_enforcement_receipt.this[0].resend_trigger == join(",", [
      terraform_data.xshield_applied_resources["ct-policy-8d612d812776"].id,
      terraform_data.xshield_applied_resources["ct-policy-d2dd5b7ea0d5"].id,
    ])
    error_message = "The receipt must be sent again whenever any group's record of its applied resources is replaced."
  }
  assert {
    condition = (terraform_data.xshield_applied_resources["ct-policy-8d612d812776"].triggers_replace == [
      azurerm_network_security_group.this["ct-policy-8d612d812776"].id,
      azurerm_subnet_network_security_group_association.this["ct-policy-8d612d812776"].id, null] &&
      terraform_data.xshield_applied_resources["ct-policy-d2dd5b7ea0d5"].triggers_replace == [
        azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].id, null,
    azurerm_network_interface_security_group_association.this["ct-policy-d2dd5b7ea0d5"].id])
    error_message = "Each group's record must be replaced when the group or its association is created again, as their IDs are unknown until then."
  }
}

run "an_association_whose_network_interface_is_gone_is_left_out" {
  override_data {
    target = data.azurerm_resources.network_interfaces
    values = { resources = [] }
  }

  assert {
    condition     = length(azurerm_network_interface_security_group_association.this) == 0 && output.interface_association_keys == []
    error_message = "An association with a deleted network interface would fail the apply."
  }
  assert {
    condition     = length(azurerm_network_security_group.this) == 2 && length(azurerm_subnet_network_security_group_association.this) == 1
    error_message = "Only the association with the deleted network interface is left out."
  }
  assert {
    condition     = length(xshield_azure_enforcement_receipt.this[0].interface_associations) == 0
    error_message = "The receipt leaves out the association it did not create, as Xshield accepts."
  }
}

run "nothing_published_creates_nothing_and_says_so" {
  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published               = false
      version                 = null
      network_security_groups = {}
      interface_associations  = {}
      subnet_associations     = {}
      assets                  = {}
    }
  }

  expect_failures = [check.xshield_published]

  assert {
    condition     = length(azurerm_network_security_group.this) == 0 && length(azurerm_network_interface_security_group_association.this) == 0 && length(azurerm_subnet_network_security_group_association.this) == 0
    error_message = "Nothing published means nothing to create."
  }
  assert {
    condition     = length(xshield_azure_enforcement_receipt.this) == 0
    error_message = "Nothing published means no receipt: there is no version to report."
  }
}

run "nothing_published_with_xshields_groups_in_the_region_stops_the_plan" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published               = false
      version                 = null
      network_security_groups = {}
      interface_associations  = {}
      subnet_associations     = {}
      assets                  = {}
    }
  }
  override_data {
    target = data.azurerm_resources.rendered
    values = {
      resources = [{
        id                  = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-d2dd5b7ea0d5"
        name                = "ct-policy-d2dd5b7ea0d5"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "East US 2"
        resource_group_name = "rg-app"
        tags                = { "ct:delivery" = "pipeline" }
      }]
    }
  }

  expect_failures = [data.azurerm_resources.rendered, check.xshield_published]
}

run "xshields_groups_in_another_region_do_not_stop_the_plan" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published               = false
      version                 = null
      network_security_groups = {}
      interface_associations  = {}
      subnet_associations     = {}
      assets                  = {}
    }
  }
  override_data {
    target = data.azurerm_resources.rendered
    values = {
      resources = [{
        id                  = "/subscriptions/sub-a/resourceGroups/rg-west/providers/Microsoft.Network/networkSecurityGroups/ct-policy-0a1b2c3d4e5f"
        name                = "ct-policy-0a1b2c3d4e5f"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "westus2"
        resource_group_name = "rg-west"
        tags                = { "ct:delivery" = "pipeline" }
      }]
    }
  }

  expect_failures = [check.xshield_published]
}

run "a_snapshot_for_another_subscription_stops_the_plan" {
  command = plan

  variables {
    cloud_account_id = "99999999-2222-3333-4444-555555555555"
  }

  expect_failures = [data.xshield_azure_enforcement_snapshot.this]
}

run "tags_cannot_set_xshields_own_in_any_case" {
  command = plan

  variables {
    tags = { "CT:Delivery" = "manual" }
  }

  expect_failures = [var.tags]
}

run "a_region_by_its_display_name_is_refused" {
  command = plan

  variables {
    region = "East US 2"
  }

  expect_failures = [var.region]
}

run "an_association_whose_virtual_network_is_gone_is_left_out" {
  override_data {
    target = data.azurerm_resources.virtual_networks
    values = { resources = [] }
  }

  assert {
    condition     = length(azurerm_subnet_network_security_group_association.this) == 0 && length(azurerm_network_interface_security_group_association.this) == 1
    error_message = "An association on a subnet that went with its virtual network would fail the apply."
  }
  assert {
    condition     = length(xshield_azure_enforcement_receipt.this[0].subnet_associations) == 0
    error_message = "The receipt leaves out the association it did not create."
  }
}

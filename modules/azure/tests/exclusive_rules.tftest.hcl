# terraform test, offline: both providers are mocked. By default each group the module creates holds only the rules
# the snapshot declares for it, so a rule added outside Terraform is removed at the next apply. Turned off, a rule
# that is not Xshield's is read back from the group and given again. The snapshot has a group on a network interface,
# which already exists, and a group on a subnet, which does not yet.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_resources" {
    defaults = { resources = [] }
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
              source_address_prefix        = "10.20.0.0/16"
              source_address_prefixes      = []
              destination_address_prefix   = "10.1.0.4/32"
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
      interface_associations = {}
      subnet_associations    = {}
      assets = {
        "web" = { level = "networkInterface", network_security_groups = ["ct-policy-d2dd5b7ea0d5"] }
        "api" = { level = "subnet", network_security_groups = ["ct-policy-8d612d812776"] }
      }
    }
  }
}

variables {
  region = "eastus2"
}

# Azure lists the subscription's groups, Xshield's on the network interface among them, in whatever case it stored
# their resource group.
override_data {
  target = data.azurerm_resources.network_security_groups
  values = {
    resources = [
      {
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/RG-APP/providers/Microsoft.Network/networkSecurityGroups/ct-policy-d2dd5b7ea0d5"
        name                = "ct-policy-d2dd5b7ea0d5"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "eastus2"
        resource_group_name = "RG-APP"
        tags                = { "ct:delivery" = "pipeline" }
      },
      {
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        name                = "nsg-web"
        type                = "Microsoft.Network/networkSecurityGroups"
        location            = "eastus2"
        resource_group_name = "rg-app"
        tags                = {}
      },
    ]
  }
}

# What the group on the network interface holds now: one of Xshield's rules, two Xshield rules an earlier version
# had, a just-in-time access rule, and an outbound rule at a priority Xshield's rules take only inbound.
override_data {
  target = data.azurerm_network_security_group.kept_rules["ct-policy-d2dd5b7ea0d5"]
  values = {
    security_rule = [
      {
        name                                       = "CT-Rule-Allow-faf81b0d4310"
        priority                                   = 501
        direction                                  = "Inbound"
        access                                     = "Allow"
        protocol                                   = "Tcp"
        source_address_prefix                      = "10.20.0.0/16"
        source_address_prefixes                    = []
        destination_address_prefix                 = "10.1.0.4/32"
        destination_address_prefixes               = []
        source_port_range                          = "*"
        source_port_ranges                         = []
        destination_port_range                     = "443"
        destination_port_ranges                    = []
        description                                = ""
        source_application_security_group_ids      = []
        destination_application_security_group_ids = []
      },
      {
        name                                       = "CT-Rule-Allow-0123456789ab"
        priority                                   = 502
        direction                                  = "Inbound"
        access                                     = "Allow"
        protocol                                   = "Tcp"
        source_address_prefix                      = "10.20.0.0/16"
        source_address_prefixes                    = []
        destination_address_prefix                 = "10.1.0.4/32"
        destination_address_prefixes               = []
        source_port_range                          = "*"
        source_port_ranges                         = []
        destination_port_range                     = "80"
        destination_port_ranges                    = []
        description                                = ""
        source_application_security_group_ids      = []
        destination_application_security_group_ids = []
      },
      {
        name                                       = "CT-Test-Rule-Allow-abcdefabcdef"
        priority                                   = 2001
        direction                                  = "Inbound"
        access                                     = "Allow"
        protocol                                   = "Tcp"
        source_address_prefix                      = "*"
        source_address_prefixes                    = []
        destination_address_prefix                 = "10.1.0.4/32"
        destination_address_prefixes               = []
        source_port_range                          = "*"
        source_port_ranges                         = []
        destination_port_range                     = "22"
        destination_port_ranges                    = []
        description                                = ""
        source_application_security_group_ids      = []
        destination_application_security_group_ids = []
      },
      {
        name                                       = "jit-allow-ssh"
        priority                                   = 1000
        direction                                  = "Inbound"
        access                                     = "Allow"
        protocol                                   = "Tcp"
        source_address_prefix                      = "203.0.113.10"
        source_address_prefixes                    = []
        destination_address_prefix                 = "10.1.0.4"
        destination_address_prefixes               = []
        source_port_range                          = "*"
        source_port_ranges                         = []
        destination_port_range                     = "22"
        destination_port_ranges                    = []
        description                                = "Just-in-time access"
        source_application_security_group_ids      = []
        destination_application_security_group_ids = []
      },
      {
        name                                       = "ops-outbound-proxy"
        priority                                   = 501
        direction                                  = "Outbound"
        access                                     = "Allow"
        protocol                                   = "Tcp"
        source_address_prefix                      = "*"
        source_address_prefixes                    = []
        destination_address_prefix                 = "10.9.0.10"
        destination_address_prefixes               = []
        source_port_range                          = "*"
        source_port_ranges                         = []
        destination_port_range                     = "3128"
        destination_port_ranges                    = []
        description                                = ""
        source_application_security_group_ids      = []
        destination_application_security_group_ids = []
      },
    ]
  }
}

run "on_by_default_each_group_holds_only_xshields_rules" {
  command = plan

  assert {
    condition     = output.exclusive_rules_enabled == true
    error_message = "rules are exclusive unless turned off"
  }
  assert {
    condition     = length(data.azurerm_resources.network_security_groups) == 0 && length(data.azurerm_network_security_group.kept_rules) == 0
    error_message = "with exclusive rules the module reads no group's rules"
  }
  assert {
    condition = (length(azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule) == 2 &&
    length(azurerm_network_security_group.this["ct-policy-8d612d812776"].security_rule) == 1)
    error_message = "each group's rule set is exactly the snapshot's, so the apply removes any other"
  }
}

run "turned_off_keeps_a_rule_added_outside_terraform" {
  command = plan

  variables {
    enable_exclusive_rules = false
  }

  assert {
    condition     = output.exclusive_rules_enabled == false
    error_message = "the output says a rule added outside Terraform stays"
  }
  assert {
    condition     = keys(data.azurerm_network_security_group.kept_rules) == ["ct-policy-d2dd5b7ea0d5"]
    error_message = "only Xshield's groups that already exist are read, whatever the case of their resource group, and never a group of the customer's"
  }
  assert {
    condition = sort([for rule in azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule : rule.name]) == tolist([
      "CT-Rule-Allow-AzureLoadBalancer", "CT-Rule-Allow-faf81b0d4310", "jit-allow-ssh", "ops-outbound-proxy",
    ])
    error_message = "the group holds Xshield's rules once each and the rules that are not Xshield's; rules an earlier version had are removed"
  }
  assert {
    condition = anytrue([for rule in azurerm_network_security_group.this["ct-policy-d2dd5b7ea0d5"].security_rule : (
      rule.name == "jit-allow-ssh" && rule.priority == 1000 && rule.direction == "Inbound" && rule.source_address_prefix == "203.0.113.10" &&
      rule.destination_port_range == "22" && rule.description == "Just-in-time access"
    )])
    error_message = "a kept rule is given again as Azure holds it, description included"
  }
  assert {
    condition     = length(azurerm_network_security_group.this["ct-policy-8d612d812776"].security_rule) == 1
    error_message = "a group that does not exist yet holds only Xshield's rules"
  }
}

run "turned_off_a_kept_rule_at_a_priority_xshield_takes_stops_the_plan" {
  command = plan

  variables {
    enable_exclusive_rules = false
  }

  override_data {
    target = data.azurerm_network_security_group.kept_rules["ct-policy-d2dd5b7ea0d5"]
    values = {
      security_rule = [
        {
          name                                       = "jit-allow-ssh"
          priority                                   = 501
          direction                                  = "Inbound"
          access                                     = "Allow"
          protocol                                   = "Tcp"
          source_address_prefix                      = "203.0.113.10"
          source_address_prefixes                    = []
          destination_address_prefix                 = "10.1.0.4"
          destination_address_prefixes               = []
          source_port_range                          = "*"
          source_port_ranges                         = []
          destination_port_range                     = "22"
          destination_port_ranges                    = []
          description                                = "Just-in-time access"
          source_application_security_group_ids      = []
          destination_application_security_group_ids = []
        },
      ]
    }
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "nothing_published_reads_no_group" {
  command = plan

  variables {
    enable_exclusive_rules = false
  }

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
    condition     = length(data.azurerm_resources.network_security_groups) == 0 && length(azurerm_network_security_group.this) == 0
    error_message = "with no group to create, no group's rules are read"
  }
}

# terraform test, offline: both providers are mocked. The snapshot below holds a database and its replica on one
# subnet, and a virtual machine on its two network interfaces, with a rule for each way the review output words
# ports and addresses, listed out of priority order. Later runs override the snapshot with another version.

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
      version   = "0123456789abcdef0123"
      network_security_groups = {
        "ct-policy-0a0a0a0a0a0a" = {
          name                = "ct-policy-0a0a0a0a0a0a"
          resource_group_name = "rg-db"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "subnet" }
          security_rules = [
            {
              name                         = "CT-Rule-Allow-Any-Outbound"
              priority                     = 4096
              direction                    = "Outbound"
              access                       = "Allow"
              protocol                     = "*"
              source_address_prefix        = "*"
              source_address_prefixes      = []
              destination_address_prefix   = "*"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "*"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Test-Rule-Allow-111111111111"
              priority                     = 2001
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "Tcp"
              source_address_prefix        = "*"
              source_address_prefixes      = []
              destination_address_prefix   = "10.1.0.6/32"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = ""
              destination_port_ranges      = ["22", "3389"]
            },
            {
              name                         = "CT-Rule-Deny-222222222222"
              priority                     = 200
              direction                    = "Inbound"
              access                       = "Deny"
              protocol                     = "*"
              source_address_prefix        = ""
              source_address_prefixes      = ["198.51.100.6/32", "198.51.100.5/32", "198.51.100.4/32", "198.51.100.3/32", "198.51.100.2/32", "198.51.100.1/32"]
              destination_address_prefix   = "*"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "*"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Allow-333333333333"
              priority                     = 501
              direction                    = "Outbound"
              access                       = "Allow"
              protocol                     = "Udp"
              source_address_prefix        = "10.1.0.6/32"
              source_address_prefixes      = []
              destination_address_prefix   = "VirtualNetwork"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "53"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Allow-444444444444"
              priority                     = 502
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "*"
              source_address_prefix        = "10.0.0.0/8"
              source_address_prefixes      = []
              destination_address_prefix   = "10.1.0.6/32"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "123"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Allow-555555555555"
              priority                     = 503
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "Icmp"
              source_address_prefix        = "10.0.0.0/8"
              source_address_prefixes      = []
              destination_address_prefix   = "10.1.0.6/32"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "*"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Allow-Any-Inbound"
              priority                     = 4096
              direction                    = "Inbound"
              access                       = "Allow"
              protocol                     = "*"
              source_address_prefix        = "*"
              source_address_prefixes      = []
              destination_address_prefix   = "*"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "*"
              destination_port_ranges      = []
            },
          ]
        }
        "ct-policy-1b1b1b1b1b1b" = {
          name                = "ct-policy-1b1b1b1b1b1b"
          resource_group_name = "rg-app"
          location            = "eastus2"
          tags                = { "ct:delivery" = "pipeline", "ct:level" = "networkInterface" }
          security_rules = [
            {
              name                         = "CT-Rule-Deny-666666666666"
              priority                     = 1501
              direction                    = "Outbound"
              access                       = "Deny"
              protocol                     = "Tcp"
              source_address_prefix        = "10.1.0.7/32"
              source_address_prefixes      = []
              destination_address_prefix   = "*"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "25"
              destination_port_ranges      = []
            },
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
              name                         = "CT-Rule-Allow-777777777777"
              priority                     = 501
              direction                    = "Outbound"
              access                       = "Allow"
              protocol                     = "Tcp"
              source_address_prefix        = "10.1.0.7/32"
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
      }
      interface_associations = {
        "ct-policy-1b1b1b1b1b1b/0" = {
          network_security_group = "ct-policy-1b1b1b1b1b1b"
          network_interface_id   = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/vm-1-nic2"
        }
        "ct-policy-1b1b1b1b1b1b/1" = {
          network_security_group = "ct-policy-1b1b1b1b1b1b"
          network_interface_id   = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/vm-1-nic"
        }
      }
      subnet_associations = {
        "ct-policy-0a0a0a0a0a0a" = {
          network_security_group = "ct-policy-0a0a0a0a0a0a"
          subnet_id              = "/subscriptions/sub-a/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-b/subnets/snet-db"
        }
      }
      assets = {
        "db-replica" = { level = "subnet", network_security_groups = ["ct-policy-0a0a0a0a0a0a"] }
        "db"         = { level = "subnet", network_security_groups = ["ct-policy-0a0a0a0a0a0a"] }
        "vm-1"       = { level = "networkInterface", network_security_groups = ["ct-policy-1b1b1b1b1b1b"] }
        "refused"    = { level = null, network_security_groups = [] }
      }
      customer_network_security_groups = {}
    }
  }
}

variables {
  region = "eastus2"
}

run "sentences_follow_priority_and_end_with_a_count" {
  command = plan

  assert {
    condition = output.review == tolist([
      "Group ct-policy-0a0a0a0a0a0a is associated with subnet snet-db of virtual network vnet-b, for assets db and db-replica.",
      "Group ct-policy-0a0a0a0a0a0a denies all inbound traffic from 198.51.100.1/32, 198.51.100.2/32, 198.51.100.3/32, 198.51.100.4/32, 198.51.100.5/32 and 1 more.",
      "Group ct-policy-0a0a0a0a0a0a allows inbound traffic on port 123 from 10.0.0.0/8 to 10.1.0.6/32.",
      "Group ct-policy-0a0a0a0a0a0a allows all inbound ICMP from 10.0.0.0/8 to 10.1.0.6/32.",
      "Group ct-policy-0a0a0a0a0a0a allows inbound TCP 22 and 3389 from anywhere to 10.1.0.6/32, logged as traffic enforce would block.",
      "Group ct-policy-0a0a0a0a0a0a allows all inbound traffic from anywhere.",
      "Group ct-policy-0a0a0a0a0a0a allows outbound UDP 53 from 10.1.0.6/32 to service tag VirtualNetwork.",
      "Group ct-policy-0a0a0a0a0a0a allows all outbound traffic to anywhere.",
      "Group ct-policy-1b1b1b1b1b1b is associated with network interfaces vm-1-nic and vm-1-nic2, for asset vm-1.",
      "Group ct-policy-1b1b1b1b1b1b allows all inbound traffic from service tag AzureLoadBalancer.",
      "Group ct-policy-1b1b1b1b1b1b allows outbound TCP 443 from 10.1.0.7/32 to service tag Storage.EastUS2.",
      "Group ct-policy-1b1b1b1b1b1b denies outbound TCP 25 from 10.1.0.7/32 to anywhere.",
      "Version 0123456789ab holds 2 groups, 10 rules, 2 interface associations and 1 subnet association for 11111111-2222-3333-4444-555555555555/eastus2.",
    ])
    error_message = "groups come by key; a group's sentences run inbound first, then in priority order, the order Azure applies them; the last sentence counts what the version holds"
  }
}

# A new rule moves the priority of each rule after it in its band, as Xshield renders them. Sentences leave the
# priority out, so only the new rule's sentence and the count change.
run "a_new_rule_changes_only_its_own_sentence" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published = true
      version   = "fedcba9876543210fedc"
      network_security_groups = {
        "ct-policy-1b1b1b1b1b1b" = {
          name                = "ct-policy-1b1b1b1b1b1b"
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
              name                         = "CT-Rule-Allow-777777777777"
              priority                     = 501
              direction                    = "Outbound"
              access                       = "Allow"
              protocol                     = "Tcp"
              source_address_prefix        = "10.1.0.7/32"
              source_address_prefixes      = []
              destination_address_prefix   = "Storage.EastUS2"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "443"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Deny-888888888888"
              priority                     = 1501
              direction                    = "Outbound"
              access                       = "Deny"
              protocol                     = "Tcp"
              source_address_prefix        = "10.1.0.7/32"
              source_address_prefixes      = []
              destination_address_prefix   = "203.0.113.0/24"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "22"
              destination_port_ranges      = []
            },
            {
              name                         = "CT-Rule-Deny-666666666666"
              priority                     = 1502
              direction                    = "Outbound"
              access                       = "Deny"
              protocol                     = "Tcp"
              source_address_prefix        = "10.1.0.7/32"
              source_address_prefixes      = []
              destination_address_prefix   = "*"
              destination_address_prefixes = []
              source_port_range            = "*"
              source_port_ranges           = []
              destination_port_range       = "25"
              destination_port_ranges      = []
            },
          ]
        }
      }
      interface_associations = {
        "ct-policy-1b1b1b1b1b1b/0" = {
          network_security_group = "ct-policy-1b1b1b1b1b1b"
          network_interface_id   = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/vm-1-nic2"
        }
        "ct-policy-1b1b1b1b1b1b/1" = {
          network_security_group = "ct-policy-1b1b1b1b1b1b"
          network_interface_id   = "/subscriptions/sub-a/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/vm-1-nic"
        }
      }
      subnet_associations = {}
      assets = {
        "vm-1" = { level = "networkInterface", network_security_groups = ["ct-policy-1b1b1b1b1b1b"] }
      }
    }
  }

  assert {
    condition = output.review == tolist([
      "Group ct-policy-1b1b1b1b1b1b is associated with network interfaces vm-1-nic and vm-1-nic2, for asset vm-1.",
      "Group ct-policy-1b1b1b1b1b1b allows all inbound traffic from service tag AzureLoadBalancer.",
      "Group ct-policy-1b1b1b1b1b1b allows outbound TCP 443 from 10.1.0.7/32 to service tag Storage.EastUS2.",
      "Group ct-policy-1b1b1b1b1b1b denies outbound TCP 22 from 10.1.0.7/32 to 203.0.113.0/24.",
      "Group ct-policy-1b1b1b1b1b1b denies outbound TCP 25 from 10.1.0.7/32 to anywhere.",
      "Version fedcba987654 holds 1 group, 4 rules, 2 interface associations and 0 subnet associations for 11111111-2222-3333-4444-555555555555/eastus2.",
    ])
    error_message = "a rule whose priority moved keeps its sentence; only the new rule's sentence is new"
  }
}

run "nothing_published_is_one_sentence" {
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

  expect_failures = [check.xshield_published]

  assert {
    condition     = output.review == tolist(["Xshield has published nothing for 11111111-2222-3333-4444-555555555555/eastus2."])
    error_message = "with nothing published, the review says so in one sentence"
  }
}

run "an_empty_version_is_one_count" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published               = true
      version                 = "v44"
      network_security_groups = {}
      interface_associations  = {}
      subnet_associations     = {}
      assets                  = {}
    }
  }

  assert {
    condition     = output.review == tolist(["Version v44 holds 0 groups, 0 rules, 0 interface associations and 0 subnet associations for 11111111-2222-3333-4444-555555555555/eastus2."])
    error_message = "a published version that holds nothing is one sentence that counts nothing"
  }
}

run "a_limit_cuts_the_review_short_and_says_so" {
  command = plan

  variables {
    review_max_groups = 1
  }

  assert {
    condition     = length(output.review) == 10 && startswith(output.review[0], "Group ct-policy-0a0a0a0a0a0a ") && alltrue([for line in slice(output.review, 0, 8) : !strcontains(line, "ct-policy-1b1b1b1b1b1b")])
    error_message = "only the first group by key is described"
  }
  assert {
    condition = slice(output.review, 8, 10) == tolist([
      "1 more group is not described here. Raise review_max_groups to describe them.",
      "Version 0123456789ab holds 2 groups, 10 rules, 2 interface associations and 1 subnet association for 11111111-2222-3333-4444-555555555555/eastus2.",
    ])
    error_message = "the groups left out are counted, and the closing count still covers the whole version"
  }
}

run "a_limit_below_zero_is_refused" {
  command = plan

  variables {
    review_max_groups = -1
  }

  expect_failures = [var.review_max_groups]
}

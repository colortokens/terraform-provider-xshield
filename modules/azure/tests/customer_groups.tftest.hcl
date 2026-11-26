# terraform test, offline: web's network interface and subnet both carry groups of yours, so Xshield's rules for web go
# into nsg-snet-owner, your subnet's group, as rule resources of this module's.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_network_security_group" {
    defaults = {
      security_rule = [
        { name = "allow-ssh", priority = 300, direction = "Inbound", access = "Allow", protocol = "Tcp", description = "", source_port_range = "*", source_port_ranges = [], destination_port_range = "22", destination_port_ranges = [], source_address_prefix = "VirtualNetwork", source_address_prefixes = [], destination_address_prefix = "*", destination_address_prefixes = [], source_application_security_group_ids = [], destination_application_security_group_ids = [] },
        { name = "CT-Rule-Allow-89dbc7f62dbc", priority = 110, direction = "Inbound", access = "Allow", protocol = "Tcp", description = "", source_port_range = "*", source_port_ranges = [], destination_port_range = "443", destination_port_ranges = [], source_address_prefix = "10.0.0.0/8", source_address_prefixes = [], destination_address_prefix = "10.1.0.4/32", destination_address_prefixes = [], source_application_security_group_ids = [], destination_application_security_group_ids = [] },
      ]
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

# Your group exists: Azure lists it in the subscription.
override_data {
  target = data.azurerm_resources.customer_network_security_groups
  values = {
    resources = [
      {
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-owner"
        name                = "nsg-snet-owner"
        type                = "Microsoft.Network/networkSecurityGroups"
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
      published                       = true
      version                         = "v44"
      network_security_groups         = {}
      interface_associations          = {}
      subnet_associations             = {}
      held_interface_associations     = {}
      held_subnet_associations        = {}
      released_interface_associations = {}
      released_subnet_associations    = {}
      assets = {
        "web" = { level = "subnet", network_security_groups = [], customer_network_security_groups = ["customer-nsg-5b8ff476f40c"] }
      }
      customer_network_security_groups = {
        "customer-nsg-5b8ff476f40c" = {
          id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-owner"
          resource_group_name = "rg-net"
          name                = "nsg-snet-owner"
          security_rules      = []
          subnets             = { "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app" = ["web"] }
        }
      }
    }
  }
  mock_data "xshield_azure_security_rules" {
    defaults = {
      published = true
      xshield_security_rules = [
        { name = "CT-Rule-Allow-64c02cd7face", description = "", priority = 100, direction = "Inbound", access = "Allow", protocol = "*", source_address_prefix = "AzureLoadBalancer", source_address_prefixes = [], source_application_security_group_ids = [], destination_address_prefix = "10.1.0.4/32", destination_address_prefixes = [], destination_application_security_group_ids = [], source_port_range = "*", source_port_ranges = [], destination_port_range = "*", destination_port_ranges = [] },
        { name = "CT-Rule-Allow-89dbc7f62dbc", description = "", priority = 110, direction = "Inbound", access = "Allow", protocol = "Tcp", source_address_prefix = "", source_address_prefixes = ["10.0.0.0/8", "172.16.0.0/12"], source_application_security_group_ids = [], destination_address_prefix = "10.1.0.4/32", destination_address_prefixes = [], destination_application_security_group_ids = [], source_port_range = "*", source_port_ranges = [], destination_port_range = "", destination_port_ranges = ["443", "8443"] },
        { name = "CT-Rule-Deny-93ef773b5a07", description = "", priority = 100, direction = "Outbound", access = "Deny", protocol = "*", source_address_prefix = "10.1.0.4/32", source_address_prefixes = [], source_application_security_group_ids = [], destination_address_prefix = "0.0.0.0/0", destination_address_prefixes = [], destination_application_security_group_ids = [], source_port_range = "*", source_port_ranges = [], destination_port_range = "*", destination_port_ranges = [] },
      ]
      security_rules = []
    }
  }
}

variables {
  region = "eastus2"
}

run "each_of_xshields_rules_goes_into_your_group_as_a_rule_resource" {
  command = plan

  assert {
    condition = sort(keys(azurerm_network_security_rule.customer)) == tolist([
      "customer-nsg-5b8ff476f40c/CT-Rule-Allow-64c02cd7face",
      "customer-nsg-5b8ff476f40c/CT-Rule-Allow-89dbc7f62dbc",
      "customer-nsg-5b8ff476f40c/CT-Rule-Deny-93ef773b5a07",
    ])
    error_message = "Each of Xshield's rules for your group must be a rule resource keyed by the group's key and the rule's name."
  }
  assert {
    condition = alltrue([for rule in azurerm_network_security_rule.customer :
    rule.network_security_group_name == "nsg-snet-owner" && rule.resource_group_name == "rg-net"])
    error_message = "Every rule must go into your group, in its resource group."
  }
  assert {
    condition     = length(azurerm_network_security_group.this) == 0
    error_message = "Your group is never recreated: the module adds rules to it."
  }
}

run "a_rule_sets_the_singular_or_the_plural_field_never_both" {
  command = plan

  assert {
    condition = (azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-64c02cd7face"].source_address_prefix == "AzureLoadBalancer"
    && azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-64c02cd7face"].source_address_prefixes == null)
    error_message = "A single source must be in source_address_prefix, with source_address_prefixes unset, as Azure refuses a service tag in the plural field."
  }
  assert {
    condition = (azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-89dbc7f62dbc"].source_address_prefix == null
      && toset(azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-89dbc7f62dbc"].source_address_prefixes) == toset(["10.0.0.0/8", "172.16.0.0/12"])
    && toset(azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-89dbc7f62dbc"].destination_port_ranges) == toset(["443", "8443"]))
    error_message = "Two or more values must be in the plural field, with the singular one unset."
  }
  assert {
    condition = (azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-89dbc7f62dbc"].priority == 110
    && azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Deny-93ef773b5a07"].direction == "Outbound")
    error_message = "A rule must keep the priority and direction the data source gives it."
  }
}

run "the_rules_are_numbered_from_the_snapshot_this_run_applies_and_the_rules_your_group_holds" {
  command = plan

  assert {
    condition     = data.xshield_azure_security_rules.customer["customer-nsg-5b8ff476f40c"].version == "v44"
    error_message = "Xshield's rules for your group must come from the snapshot version the enforcement snapshot gives, not a later one."
  }
  assert {
    condition = jsonencode(data.xshield_azure_security_rules.customer["customer-nsg-5b8ff476f40c"].current_security_rules) == jsonencode([
      { name = "allow-ssh", priority = 300, direction = "Inbound" },
      { name = "CT-Rule-Allow-89dbc7f62dbc", priority = 110, direction = "Inbound" },
    ])
    error_message = "The data source must be given every rule your group holds now, yours and Xshield's, so it keeps Xshield's at their priorities and below yours."
  }
  assert {
    condition     = endswith(data.xshield_azure_security_rules.customer["customer-nsg-5b8ff476f40c"].network_security_group_id, "/networkSecurityGroups/nsg-snet-owner")
    error_message = "The data source must be read for your group by its resource ID."
  }
}

run "a_group_whose_configuration_declares_its_rules_inline_is_left_to_it" {
  command = plan

  variables {
    customer_network_security_groups_in_code = ["/SUBSCRIPTIONS/11111111-2222-3333-4444-555555555555/resourceGroups/RG-NET/providers/Microsoft.Network/networkSecurityGroups/NSG-SNET-OWNER"]
  }

  assert {
    condition     = length(data.azurerm_network_security_group.customer) == 0 && length(data.xshield_azure_security_rules.customer) == 0 && length(azurerm_network_security_rule.customer) == 0
    error_message = "A group listed as declared in code must get no rule resource, whatever the case of its ID, as an apply of its inline rules would remove them."
  }
}

run "applying_sends_the_receipt_again_when_a_rule_in_your_group_is_written" {
  assert {
    condition     = length(terraform_data.xshield_applied_customer_rules) == 1
    error_message = "A rule written into your group must change the receipt's resend trigger, so Xshield observes the group at once."
  }
  assert {
    condition     = strcontains(xshield_azure_enforcement_receipt.this[0].resend_trigger, terraform_data.xshield_applied_customer_rules[0].id)
    error_message = "The receipt's resend trigger must carry the record of the rules written into your group."
  }
}

run "nothing_for_your_groups_writes_no_rule_and_keeps_no_record" {
  command = plan

  override_data {
    target = data.xshield_azure_enforcement_snapshot.this
    values = {
      published                        = true
      version                          = "v45"
      assets                           = {}
      customer_network_security_groups = {}
    }
  }

  assert {
    condition     = length(azurerm_network_security_rule.customer) == 0 && length(terraform_data.xshield_applied_customer_rules) == 0
    error_message = "A version that writes nothing into your groups must remove the rules an earlier one wrote, and keep no record of them."
  }
}

run "a_group_of_yours_deleted_before_xshield_observes_it_fails_no_plan" {
  command = plan

  override_data {
    target = data.azurerm_resources.customer_network_security_groups
    values = { resources = [] }
  }

  assert {
    condition     = length(data.azurerm_network_security_group.customer) == 0 && length(azurerm_network_security_rule.customer) == 0
    error_message = "A group of yours that Azure no longer lists must be neither read, which fails the plan, nor given rules."
  }
}

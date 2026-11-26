# terraform test, offline: both providers are mocked. recovery.tf is a file for the enforcement workspace, so it is
# tested in one: copy ../enforcement-azure/main.tf, recovery.tf and this tests directory into an empty directory beside
# recovery-azure/, and run terraform init and terraform test there. A mock provider refuses an import with no override,
# so each run fails if it imports an address the module does not declare.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "11111111-2222-3333-4444-555555555555" }
  }
  mock_data "azurerm_subnet" {
    defaults = { network_security_group_id = "" }
  }
  mock_data "azurerm_virtual_network" {
    defaults = { subnets = ["snet-app", "snet-db"] }
  }
  mock_data "azurerm_network_security_group" {
    defaults = { security_rule = [] }
  }
}

override_data {
  target = module.xshield_enforcement.data.azurerm_resources.network_interfaces
  values = { resources = [
    for nic in ["nic-web", "nic-old"] : {
      id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/${nic}"
      name                = nic
      type                = "Microsoft.Network/networkInterfaces"
      location            = "eastus2"
      resource_group_name = "rg-app"
      tags                = {}
    }
  ] }
}

override_data {
  target = module.xshield_enforcement.data.azurerm_resources.virtual_networks
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
  target = module.xshield_enforcement.data.azurerm_resources.xshield_network_security_groups
  values = { resources = [] }
}

override_data {
  target = module.xshield_enforcement.data.azurerm_resources.customer_network_security_groups
  values = { resources = [{
    id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-yours"
    name                = "nsg-yours"
    type                = "Microsoft.Network/networkSecurityGroups"
    location            = "eastus2"
    resource_group_name = "rg-net"
    tags                = {}
  }] }
}

override_data {
  target = module.xshield_enforcement.data.azurerm_network_interface.leaving["ct-policy-cccccccccccc"]
  values = { name = "nic-old", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/nsg-app-team" }
}

override_data {
  target = module.xshield_enforcement.data.azurerm_subnet.contained["ct-policy-dddddddddddd"]
  values = { name = "snet-db", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-managed-nsg-snet-db" }
}

mock_provider "xshield" {
  mock_data "xshield_azure_enforcement_snapshot" {
    defaults = {
      cloud_account_id = "11111111-2222-3333-4444-555555555555"
      region           = "eastus2"
      published        = true
      version          = "v7"
      network_security_groups = {
        "ct-policy-aaaaaaaaaaaa" = { name = "ct-policy-aaaaaaaaaaaa", resource_group_name = "rg-app", location = "eastus2", tags = { "ct:delivery" = "pipeline" }, security_rules = [] }
        "ct-policy-bbbbbbbbbbbb" = { name = "ct-policy-bbbbbbbbbbbb", resource_group_name = "rg-net", location = "eastus2", tags = { "ct:delivery" = "pipeline" }, security_rules = [] }
      }
      interface_associations = {
        "ct-policy-aaaaaaaaaaaa" = { network_security_group = "ct-policy-aaaaaaaaaaaa", network_interface_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web" }
      }
      subnet_associations = {
        "ct-policy-bbbbbbbbbbbb" = { network_security_group = "ct-policy-bbbbbbbbbbbb", subnet_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app" }
      }
      held_interface_associations = {
        "ct-policy-cccccccccccc" = {
          level_id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old"
          network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-cccccccccccc"
        }
      }
      contained_subnet_associations = {
        "ct-policy-dddddddddddd" = {
          level_id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-db"
          network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-dddddddddddd"
        }
      }
      held_subnet_associations         = {}
      contained_interface_associations = {}
      released_interface_associations  = {}
      released_subnet_associations     = {}
      handover_interface_associations  = {}
      handover_subnet_associations     = {}
      assets                           = {}
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
  mock_data "xshield_azure_enforcement_status" {
    defaults = {
      cloud_account_id = "11111111-2222-3333-4444-555555555555"
      region           = "eastus2"
      applied_version  = "v7"
      applied_network_security_groups = {
        "ct-policy-aaaaaaaaaaaa" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa"
        "ct-policy-bbbbbbbbbbbb" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb"
      }
      applied_interface_associations = {
        "ct-policy-aaaaaaaaaaaa" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa"
      }
      applied_subnet_associations = {
        "ct-policy-bbbbbbbbbbbb" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app"
      }
      notices        = []
      drift_findings = []
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

override_resource {
  target = module.xshield_enforcement.azurerm_network_security_group.this["ct-policy-aaaaaaaaaaaa"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa" }
}
override_resource {
  target = module.xshield_enforcement.azurerm_network_security_group.this["ct-policy-bbbbbbbbbbbb"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb" }
}
override_resource {
  target = module.xshield_enforcement.azurerm_network_interface_security_group_association.this["ct-policy-aaaaaaaaaaaa"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa" }
}
override_resource {
  target = module.xshield_enforcement.azurerm_network_interface_security_group_association.this["ct-policy-cccccccccccc"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-cccccccccccc" }
}
override_resource {
  target = module.xshield_enforcement.azurerm_subnet_network_security_group_association.this["ct-policy-bbbbbbbbbbbb"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app" }
}
override_resource {
  target = module.xshield_enforcement.azurerm_subnet_network_security_group_association.this["ct-policy-dddddddddddd"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-db" }
}
override_resource {
  target = module.xshield_enforcement.azurerm_network_security_rule.customer["customer-nsg-5b8ff476f40c/CT-Rule-Allow-64c02cd7face"]
  values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-yours/securityRules/CT-Rule-Allow-64c02cd7face" }
}
override_resource {
  target = module.xshield_enforcement.xshield_azure_enforcement_receipt.this[0]
  values = { id = "receipt-1" }
}

# A mock provider builds an imported object from its configuration and refuses an unknown value in it, so everything the
# receipt reads is given a value at plan.
override_resource {
  target          = module.xshield_enforcement.terraform_data.xshield_applied_resources
  override_during = plan
  values          = { id = "record" }
}
override_resource {
  target          = module.xshield_enforcement.terraform_data.xshield_applied_customer_rules
  override_during = plan
  values          = { id = "record" }
}

variables {
  subscription_id = "11111111-2222-3333-4444-555555555555"
  region          = "eastus2"
}

run "the_receipt_and_what_it_leaves_out_are_imported_at_the_modules_addresses" {
  command = plan

  assert {
    condition     = keys(local.recovered_network_security_groups) == ["ct-policy-aaaaaaaaaaaa", "ct-policy-bbbbbbbbbbbb"]
    error_message = "Each group the receipt names must be imported."
  }
  assert {
    condition = local.recovered_interface_associations == {
      "ct-policy-aaaaaaaaaaaa" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-web|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-aaaaaaaaaaaa"
      "ct-policy-cccccccccccc" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-old|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-cccccccccccc"
    }
    error_message = "The receipt's interface association and the one Xshield holds, which the receipt leaves out, must both be imported."
  }
  assert {
    condition = local.recovered_subnet_associations == {
      "ct-policy-bbbbbbbbbbbb" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app"
      "ct-policy-dddddddddddd" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-db"
    }
    error_message = "The receipt's subnet association and the contained workload's, which the receipt leaves out, must both be imported."
  }
  assert {
    condition     = keys(local.recovered_security_rules) == ["customer-nsg-5b8ff476f40c/CT-Rule-Allow-64c02cd7face"]
    error_message = "Xshield's rule in your group, which the receipt leaves out, must be imported."
  }
}

run "an_association_the_module_no_longer_declares_is_not_imported" {
  command = plan

  override_data {
    target = module.xshield_enforcement.data.azurerm_network_interface.leaving["ct-policy-cccccccccccc"]
    values = { name = "nic-old", network_security_group_id = "" }
  }
  override_data {
    target = module.xshield_enforcement.data.azurerm_virtual_network.subnet_levels
    values = { subnets = ["snet-app"] }
  }

  assert {
    condition     = keys(local.recovered_interface_associations) == ["ct-policy-aaaaaaaaaaaa"] && keys(local.recovered_subnet_associations) == ["ct-policy-bbbbbbbbbbbb"]
    error_message = "A held association whose interface now carries no group, and a contained one whose subnet is gone, are not declared, so importing them would fail the plan."
  }
}

run "an_association_the_connector_handed_over_is_imported_from_the_receipt" {
  command = plan

  override_data {
    target = module.xshield_enforcement.data.azurerm_resources.network_interfaces
    values = { resources = [
      for nic in ["nic-web", "nic-old", "nic-handed"] : {
        id                  = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/${nic}"
        name                = nic
        type                = "Microsoft.Network/networkInterfaces"
        location            = "eastus2"
        resource_group_name = "rg-app"
        tags                = {}
      }
    ] }
  }
  override_data {
    target = module.xshield_enforcement.data.xshield_azure_enforcement_snapshot.this
    values = {
      cloud_account_id = "11111111-2222-3333-4444-555555555555"
      region           = "eastus2"
      published        = true
      version          = "v7"
      network_security_groups = {
        "ct-policy-eeeeeeeeeeee" = { name = "ct-policy-eeeeeeeeeeee", resource_group_name = "rg-app", location = "eastus2", tags = { "ct:delivery" = "pipeline" }, security_rules = [] }
      }
      interface_associations = {}
      subnet_associations    = {}
      handover_interface_associations = {
        "ct-policy-eeeeeeeeeeee" = { network_security_group = "ct-policy-eeeeeeeeeeee", network_interface_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-handed" }
      }
      handover_subnet_associations     = {}
      held_interface_associations      = {}
      held_subnet_associations         = {}
      contained_interface_associations = {}
      contained_subnet_associations    = {}
      released_interface_associations  = {}
      released_subnet_associations     = {}
      assets                           = {}
      customer_network_security_groups = {}
    }
  }
  override_data {
    target = module.xshield_enforcement.data.azurerm_network_interface.handover["ct-policy-eeeeeeeeeeee"]
    values = { name = "nic-handed", network_security_group_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-eeeeeeeeeeee" }
  }
  override_data {
    target = data.xshield_azure_enforcement_status.recover
    values = {
      cloud_account_id = "11111111-2222-3333-4444-555555555555"
      region           = "eastus2"
      applied_version  = "v7"
      applied_network_security_groups = {
        "ct-policy-eeeeeeeeeeee" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-eeeeeeeeeeee"
      }
      applied_interface_associations = {
        "ct-policy-eeeeeeeeeeee" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-handed|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-eeeeeeeeeeee"
      }
      applied_subnet_associations = {}
      notices                     = []
      drift_findings              = []
    }
  }
  override_resource {
    target = module.xshield_enforcement.azurerm_network_security_group.this["ct-policy-eeeeeeeeeeee"]
    values = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-eeeeeeeeeeee" }
  }
  override_resource {
    target          = module.xshield_enforcement.azurerm_network_interface_security_group_association.this["ct-policy-eeeeeeeeeeee"]
    override_during = plan
    values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-handed|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-eeeeeeeeeeee" }
  }

  assert {
    condition = local.recovered_interface_associations == {
      "ct-policy-eeeeeeeeeeee" = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-handed|/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/ct-policy-eeeeeeeeeeee"
    }
    error_message = "An association the cloud connector handed over, which the receipt holds and the version still lists as a handover association, must be imported, or the apply tries to create it on a level that already carries the group."
  }
}

run "a_skipped_import_is_left_to_the_apply" {
  command = plan

  variables {
    skipped_imports = { network_security_groups = ["ct-policy-bbbbbbbbbbbb"], subnet_associations = ["ct-policy-bbbbbbbbbbbb"] }
  }
  override_resource {
    target          = module.xshield_enforcement.azurerm_network_security_group.this["ct-policy-bbbbbbbbbbbb"]
    override_during = plan
    values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/ct-policy-bbbbbbbbbbbb" }
  }
  override_resource {
    target          = module.xshield_enforcement.azurerm_subnet_network_security_group_association.this["ct-policy-bbbbbbbbbbbb"]
    override_during = plan
    values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app" }
  }

  assert {
    condition     = keys(local.recovered_network_security_groups) == ["ct-policy-aaaaaaaaaaaa"] && keys(local.recovered_subnet_associations) == ["ct-policy-dddddddddddd"]
    error_message = "A group or association deleted since the receipt must be left out of the imports, so the apply creates it again."
  }
}

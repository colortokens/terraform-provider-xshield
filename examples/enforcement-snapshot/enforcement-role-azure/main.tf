# The role the Azure enforcement workspace runs as, created once per subscription
# by whoever owns access control there. ColorTokens never holds it. It grants
# network security group, network interface and subnet writes only: no compute,
# identity or data access.
#
# Azure has no condition that limits these writes to Xshield's own resources, as
# AWS limits them to tagged ones. Assign the role on the resource groups that
# hold your workloads' network interfaces and subnets, rather than the whole
# subscription, to keep its reach to those. The enforcement module creates each
# of Xshield's groups in the resource group of the interface or subnet it
# protects.
#
# Associating a group rewrites the whole network interface or subnet, and Azure
# checks a join action on every resource it links to, changed or not. The role
# names the join for each link the network interface and subnet APIs carry, so
# it holds whatever your interfaces and subnets link to: a VM, a scale set
# instance in flexible mode, a database's or a Function App's subnet alike.
# A join is checked where the linked resource is, so a scope list must also
# hold the resource groups of linked resources, such as a hub's route tables
# or shared public IP addresses.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.81.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
}

variable "subscription_id" {
  description = "Azure subscription the enforcement workspace enforces."
  type        = string
}

variable "pipeline_principal_ids" {
  description = "Object IDs of the identities your Terraform runner uses for the enforcement workspace: a service principal or a managed identity."
  type        = list(string)

  validation {
    condition     = length(var.pipeline_principal_ids) > 0
    error_message = "pipeline_principal_ids lists no identity, so nothing could run the enforcement workspace."
  }
}

variable "scopes" {
  description = "Resource IDs to assign the role on: the resource groups that hold your workloads' network interfaces and subnets. The whole subscription by default."
  type        = list(string)
  default     = null

  validation {
    condition     = var.scopes == null || length(coalesce(var.scopes, [])) > 0
    error_message = "scopes lists nothing, which leaves the role assigned nowhere: leave it unset for the whole subscription, or list the resource groups that hold your workloads."
  }
}

locals {
  subscription = "/subscriptions/${var.subscription_id}"
  scopes       = coalesce(var.scopes, [local.subscription])
}

resource "azurerm_role_definition" "enforcement" {
  name        = "Xshield enforcement (${var.subscription_id})"
  scope       = local.subscription
  description = "Applies the network security groups Xshield renders, and associates them with network interfaces and subnets."

  assignable_scopes = [local.subscription]

  permissions {
    actions = [
      # The module lists the subscription's network security groups and network interfaces, and polls Azure's long-running
      # operations.
      "Microsoft.Resources/subscriptions/resources/read",
      "Microsoft.Network/locations/operations/read",

      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkSecurityGroups/write",
      "Microsoft.Network/networkSecurityGroups/delete",
      "Microsoft.Network/networkSecurityGroups/join/action",

      "Microsoft.Network/networkInterfaces/read",
      "Microsoft.Network/networkInterfaces/write",
      "Microsoft.Network/virtualNetworks/read",
      "Microsoft.Network/virtualNetworks/subnets/read",
      "Microsoft.Network/virtualNetworks/subnets/write",

      # What a network interface's IP configurations can link to.
      "Microsoft.Network/virtualNetworks/subnets/join/action",
      "Microsoft.Network/publicIPAddresses/join/action",
      "Microsoft.Network/applicationSecurityGroups/joinIpConfiguration/action",
      "Microsoft.Network/loadBalancers/backendAddressPools/join/action",
      "Microsoft.Network/loadBalancers/inboundNatRules/join/action",
      "Microsoft.Network/loadBalancers/frontendIPConfigurations/join/action",
      "Microsoft.Network/applicationGateways/backendAddressPools/join/action",
      "Microsoft.Network/virtualNetworkTaps/join/action",

      # What a subnet can link to.
      "Microsoft.Network/routeTables/join/action",
      "Microsoft.Network/natGateways/join/action",
      "Microsoft.Network/serviceEndpointPolicies/join/action",
      "Microsoft.Network/serviceEndpointPolicies/joinSubnet/action",
      "Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action",
      "Microsoft.Network/publicIPAddresses/joinServiceEndpointNetworkIdentifier/action",
      "Microsoft.Network/networkManagers/ipamPools/associateResourcesToPool/action",
    ]
  }
}

resource "azurerm_role_assignment" "enforcement" {
  for_each = { for pair in setproduct(local.scopes, var.pipeline_principal_ids) : "${pair[0]}|${pair[1]}" => { scope = pair[0], principal_id = pair[1] } }

  scope              = each.value.scope
  role_definition_id = azurerm_role_definition.enforcement.role_definition_resource_id
  principal_id       = each.value.principal_id
}

output "role_definition_id" {
  description = "The role's resource ID."
  value       = azurerm_role_definition.enforcement.role_definition_resource_id
}

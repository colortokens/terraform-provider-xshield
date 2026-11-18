# The enforcement workspace for Azure: one per subscription and region. It
# applies what Xshield rendered. The Xshield API key comes from the XSHIELD_*
# environment variables, and the azurerm provider's credentials from the ARM_*
# ones, so nothing secret lives in this file.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.81.0"
    }
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "xshield" {}

module "xshield_enforcement" {
  # ../modules/azure exists only inside the provider's repository. In your copy, use the address at the tag
  # of the provider release you run, or terraform init cannot find the module:
  #   source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/azure?ref=vX.Y.Z"
  source = "../modules/azure"

  region = var.region
  tags   = { "cost-center" = "platform-security" }
}

variable "subscription_id" {
  description = "Azure subscription this workspace enforces."
  type        = string
}

variable "region" {
  description = "Azure region this workspace enforces, by its name, such as eastus2."
  type        = string
}

output "summary" {
  description = "What the applied version holds, for plan review and run logs."
  value       = module.xshield_enforcement.summary
}

output "xshield_review" {
  description = "What the applied version holds, in words. A plan lists the sentences that change."
  value       = module.xshield_enforcement.review
}

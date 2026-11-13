# The enforcement workspace: one per AWS account and region. It applies what
# Xshield rendered and reports the apply. The Xshield API key comes from the
# XSHIELD_* environment variables, so nothing secret lives in this file.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.29.0"
    }
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

provider "aws" {
  region = var.region

  assume_role {
    role_arn = var.enforcement_role_arn
  }
}

provider "xshield" {}

module "xshield_enforcement" {
  source = "../modules/aws"

  tags = { "cost-center" = "platform-security" }
}

variable "region" {
  description = "AWS region this workspace enforces."
  type        = string
}

variable "enforcement_role_arn" {
  description = "Role the pipeline assumes in the account; see the role permissions in the README."
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

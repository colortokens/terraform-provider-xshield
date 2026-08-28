# =============================================================================
# APPLICATION workspace - what an app team actually writes.
#
# Note what is NOT here: no ColorTokens provider, no credential, no endpoint,
# no segment name, no policy version. Just the workload's own tags.
#
# In a real estate this lookup lives inside your golden compute module, so most
# app teams write ZERO ColorTokens-aware lines: they set their standard tags and
# the platform module attaches the right groups.
# =============================================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  access_key                  = var.demo_mode ? "test" : null
  secret_key                  = var.demo_mode ? "test" : null
  skip_credentials_validation = var.demo_mode
  skip_requesting_account_id  = var.demo_mode
  skip_metadata_api_check     = var.demo_mode
}

locals {
  # The tags this workload already carries under the org tagging standard.
  workload_tags = merge(
    {
      environment = var.environment
      application = var.application
      tier        = var.tier
    },
    var.additional_tags,
  )
}

# ---- the only ColorTokens-aware line in an application workspace ------------
module "ct" {
  source = "../modules/ct-workload-lookup"

  tags = local.workload_tags
  # tag_keys / directory_prefix default to the org standard; set once in your
  # golden module if yours differs.
}

# ---- the workload -----------------------------------------------------------
# Illustrative; in production this is your golden compute module and the only
# change is `concat(..., module.ct.security_group_ids)`.
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id

  vpc_security_group_ids = concat(var.base_security_group_ids, module.ct.security_group_ids)

  tags = merge(local.workload_tags, { Name = var.name })
}

# Autoscaling note: put the same `vpc_security_group_ids` on your launch
# template instead, and every scaled-out instance is enforced at birth with no
# pipeline involvement whatsoever:
#
# resource "aws_launch_template" "app" {
#   name_prefix            = "${var.name}-"
#   image_id               = var.ami_id
#   instance_type          = var.instance_type
#   vpc_security_group_ids = concat(var.base_security_group_ids, module.ct.security_group_ids)
#   tag_specifications {
#     resource_type = "instance"
#     tags          = local.workload_tags
#   }
# }

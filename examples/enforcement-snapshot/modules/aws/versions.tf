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

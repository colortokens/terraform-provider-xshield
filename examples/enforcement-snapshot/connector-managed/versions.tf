terraform {
  required_version = ">= 1.7.0"
  required_providers {
    xshield = {
      source  = "colortokens/xshield"
      version = ">= 0.1.0"
    }
  }
}

provider "xshield" {
  server_url       = var.xshield_server_url
  tenancy_id       = var.xshield_tenancy_id
  user_id          = var.xshield_user_id
  fingerprint      = var.xshield_fingerprint
  private_key_path = var.xshield_private_key_path
}

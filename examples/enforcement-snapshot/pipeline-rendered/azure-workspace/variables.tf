variable "subscription_id" {
  description = "Azure subscription the enforcement resources are created in."
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  type    = string
  default = "ct-enforcement"
}

variable "network_security_group_name" {
  type    = string
  default = "ct-enforcement-nsg"
}

variable "app_configuration_name" {
  description = "Must be globally unique within Azure."
  type        = string
  default     = "ct-directory-example"
}

# ---- scope of the snapshot being rendered ------------------------------------
# Kept distinct from the Azure placement variables above: an Xshield snapshot is
# scoped by the cloud account/region it was compiled for.
variable "cloud_account_id" {
  description = "Cloud account/subscription the snapshot was compiled for."
  type        = string
  default     = "123456789012"
}

variable "cloud_region" {
  description = "Cloud region the snapshot was compiled for."
  type        = string
  default     = "us-east-1"
}

# ---- Xshield connection ------------------------------------------------------
variable "xshield_server_url" {
  type    = string
  default = "http://localhost:8087"
}

variable "xshield_tenancy_id" {
  type    = string
  default = "demo-tenant"
}

variable "xshield_user_id" {
  type    = string
  default = "ct-enforcement-bot"
}

variable "xshield_fingerprint" {
  type    = string
  default = "demo"
}

variable "xshield_private_key_path" {
  type      = string
  default   = "../../demo-signing-key.pem"
  sensitive = true
}

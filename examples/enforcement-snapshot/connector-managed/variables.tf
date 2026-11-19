variable "xshield_server_url" {
  description = "Xshield API base URL."
  type        = string
}

variable "xshield_tenancy_id" {
  description = "Tenancy ID of the API key, shown with the key in Xshield under Settings > API Keys."
  type        = string
}

variable "xshield_user_id" {
  description = "Principal for policy authoring. Needs CREATE/UPDATE on templates and segments, and DEPLOY_POLICY only if the deployment trigger is enabled."
  type        = string
}

variable "xshield_fingerprint" {
  description = "Fingerprint of the API key."
  type        = string
}

variable "xshield_private_key_path" {
  description = "Path to the API key's PEM private key."
  type        = string
  sensitive   = true
}

variable "enable_deployment_trigger" {
  description = "false = author policy only (deployment stays a human action in Xshield). true = the pipeline also moves policy to the requested mode."
  type        = bool
  default     = false
}

variable "deployment_mode" {
  description = "test | enforce | undeploy."
  type        = string
  default     = "test"

  validation {
    condition     = contains(["test", "enforce", "undeploy"], var.deployment_mode)
    error_message = "deployment_mode must be one of: test, enforce, undeploy."
  }
}

variable "change_ticket" {
  description = "Change record reference; required when deployment_mode is 'enforce'."
  type        = string
  default     = ""
}

variable "xshield_server_url" {
  description = "Xshield API base URL."
  type        = string
}

variable "xshield_tenancy_id" {
  type = string
}

variable "xshield_user_id" {
  description = "Principal for policy authoring. Needs CREATE/UPDATE on templates and segments, and DEPLOY_POLICY only if the deployment trigger is enabled."
  type        = string
}

variable "xshield_fingerprint" {
  type = string
}

variable "xshield_private_key_path" {
  type      = string
  sensitive = true
}

variable "enable_deployment_trigger" {
  description = "false = author policy only (deployment stays a human action in Xshield). true = the pipeline also moves policy to the requested mode."
  type        = bool
  default     = false
}

variable "deployment_mode" {
  description = "test | enforced | undeploy."
  type        = string
  default     = "test"

  validation {
    condition     = contains(["test", "enforced", "undeploy"], var.deployment_mode)
    error_message = "deployment_mode must be one of: test, enforced, undeploy."
  }
}

variable "change_ticket" {
  description = "Change record reference; required when deployment_mode is 'enforced'."
  type        = string
  default     = ""
}

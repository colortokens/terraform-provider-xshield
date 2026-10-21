variable "xshield_server_url" {
  type = string
}

variable "xshield_tenancy_id" {
  type = string
}

variable "xshield_user_id" {
  description = "Principal with read access to enforcement status only."
  type        = string
}

variable "xshield_fingerprint" {
  type = string
}

variable "xshield_private_key_path" {
  type      = string
  sensitive = true
}

variable "cloud_account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "max_pending_hours" {
  description = "How long approved policy may wait for an enforcement run before this warns."
  type        = number
  default     = 24
}

variable "max_silence_hours" {
  description = "How long the enforcement pipeline may go without planning before this warns. Set above your run cadence."
  type        = number
  default     = 26
}

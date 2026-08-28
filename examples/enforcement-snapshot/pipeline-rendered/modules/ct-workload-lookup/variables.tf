variable "tags" {
  description = "The tags this workload already carries. The only input the app team supplies."
  type        = map(string)
}

variable "tag_keys" {
  description = "Org tagging-standard keys, in hierarchy order (most general first). Set once in your golden module so app teams never think about it."
  type        = list(string)
  default     = ["environment", "application", "tier"]

  validation {
    condition     = length(var.tag_keys) > 0
    error_message = "tag_keys must contain at least one key."
  }
}

variable "directory_prefix" {
  description = "SSM namespace the enforcement workspace publishes the workload directory to."
  type        = string
  default     = "/colortokens/v1"
}

variable "strict" {
  description = "true (default) = a workload whose tags match no segment fails the plan. Set false only for a deliberate, time-boxed migration window."
  type        = bool
  default     = true
}

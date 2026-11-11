variable "cloud_account_id" {
  description = "AWS account to enforce. Defaults to the account the AWS provider is configured for; set it only to make the target explicit."
  type        = string
  default     = null
}

variable "region" {
  description = "AWS region to enforce. Defaults to the region the AWS provider is configured for."
  type        = string
  default     = null
}

variable "snapshot_version" {
  description = "Pins a snapshot version, its content hash, for break-glass rollback or forensics. Leave unset to apply the version Xshield expects; while a pin is in place, Xshield reports the account as pending."
  type        = string
  default     = null
}

variable "workspace" {
  description = "Name Xshield shows for the workspace that applied a version. Defaults to xshield-enforcement-<account>-<region>."
  type        = string
  default     = null
}

variable "review_max_groups" {
  description = "How many groups the review output describes in words. Cohort groups come first, then the rest by key. Groups past this number are counted, not described."
  type        = number
  default     = 50

  validation {
    condition     = var.review_max_groups >= 0 && floor(var.review_max_groups) == var.review_max_groups
    error_message = "review_max_groups must be a whole number, zero or more."
  }
}

variable "tags" {
  description = "Tags added to every resource this module creates. Xshield's own tags, which the cloud connector reads, cannot be overridden."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.tags) : k != "ManagedBy" && !startswith(k, "ct:")])
    error_message = "tags cannot set ManagedBy or a key starting with ct:. The cloud connector reads those to recognise Xshield's groups."
  }
}

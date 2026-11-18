variable "cloud_account_id" {
  description = "Azure subscription ID to enforce. Defaults to the subscription the azurerm provider is configured for; set it only to make the target explicit."
  type        = string
  default     = null
}

variable "region" {
  description = "Azure region to enforce, by its name, such as eastus2. Xshield publishes one snapshot for each region its workloads in the subscription are in."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9]+$", var.region))
    error_message = "region is the region's name, such as eastus2, not its display name, such as East US 2."
  }
}

variable "snapshot_version" {
  description = "Pins a snapshot version, its content hash, for break-glass rollback or forensics. Leave unset to apply the version Xshield expects."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags added to every network security group this module creates. Xshield's own tags, which the cloud connector reads, cannot be overridden."
  type        = map(string)
  default     = {}
  nullable    = false

  validation {
    condition     = alltrue([for k in keys(var.tags) : !startswith(lower(k), "ct:")])
    error_message = "tags cannot set a key starting with ct:, in any case. The cloud connector reads those to recognise Xshield's network security groups, and Azure takes tag names that differ only in case as one."
  }
}

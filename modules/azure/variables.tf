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

variable "workspace" {
  description = "Name Xshield shows for the workspace that applied a version. Defaults to xshield-enforcement-<subscription>-<region>."
  type        = string
  default     = null
}

variable "enable_exclusive_rules" {
  description = "Whether each network security group this module creates holds only the rules the snapshot declares for it, so the next apply removes a rule added to one of them outside Terraform. Set it to false to leave such a rule in place until a person removes it. Network security groups of your own are never managed this way."
  type        = bool
  default     = true
  nullable    = false
}

variable "customer_network_security_groups_in_code" {
  description = "Resource IDs of network security groups of yours whose rules a Terraform configuration declares inline. Xshield writes a workload's rules into your subnet's group when every network interface or subnet of the workload carries a group of yours, and this module adds them to the group as rule resources. An apply of inline rules removes every rule it does not declare, so for a group listed here the module adds nothing: its configuration passes its rules through the xshield_azure_security_rules data source and declares the rules that come back."
  type        = set(string)
  default     = []
  nullable    = false
}

variable "review_max_groups" {
  description = "How many groups the review output describes in words, by key. Groups past this number are counted, not described."
  type        = number
  default     = 50

  validation {
    condition     = var.review_max_groups >= 0 && floor(var.review_max_groups) == var.review_max_groups
    error_message = "review_max_groups must be a whole number, zero or more."
  }
}

variable "tags" {
  description = "Tags added to every network security group this module creates. Xshield's own tags, which the cloud connector reads, cannot be overridden."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.tags) : !startswith(lower(k), "ct:")])
    error_message = "tags cannot set a key starting with ct:, in any case. The cloud connector reads those to recognise Xshield's network security groups, and Azure takes tag names that differ only in case as one."
  }
}

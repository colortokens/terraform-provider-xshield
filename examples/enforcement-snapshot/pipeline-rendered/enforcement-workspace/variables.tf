# ---- Xshield connection ------------------------------------------------------

variable "xshield_server_url" {
  description = "Xshield API base URL (e.g. https://ng.<tenant>.colortokens.com)."
  type        = string
}

variable "xshield_tenancy_id" {
  description = "Xshield tenant identifier."
  type        = string
}

variable "xshield_user_id" {
  description = "Principal (service account) the enforcement workspace authenticates as. Needs READ_CLOUD_POLICY_SNAPSHOT and REPORT_CLOUD_POLICY_APPLY only."
  type        = string
}

variable "xshield_fingerprint" {
  description = "API key fingerprint for the signing key."
  type        = string
}

variable "xshield_private_key_path" {
  description = "Path to the PEM signing key on the runner. In TFE/HCP supply it via a file-type workspace variable, or use OIDC workload identity when available."
  type        = string
  sensitive   = true
}

# ---- Cloud scope -------------------------------------------------------------

variable "cloud_account_id" {
  description = "AWS account ID this workspace enforces."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.cloud_account_id))
    error_message = "cloud_account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "AWS region this workspace enforces (one workspace per account x region)."
  type        = string
}

variable "vpc_id" {
  description = "VPC the ColorTokens security groups are created in. NOTE: this example renders a single VPC; a group whose members span VPCs fails a precondition rather than mis-rendering."
  type        = string
}

# ---- Governance --------------------------------------------------------------

variable "max_quarantined_assets" {
  description = "Plan surfaces a warning when the snapshot's quarantined asset count exceeds this. 0 = strict. The HARD gate belongs in Sentinel (ct-conformance-watch)."
  type        = number
  default     = 0
}

variable "directory_prefix" {
  description = "SSM Parameter Store namespace for the workload directory. Must be write-protected to this workspace's role by SCP/IAM (see iam-guardrails.md)."
  type        = string
  default     = "/colortokens/v1"
}

variable "directory_kms_key_id" {
  description = "Optional KMS key for SecureString directory parameters. Null = String type (the directory holds no secrets, only security group IDs, but some estates require CMK on all parameters)."
  type        = string
  default     = null
}

variable "prefix_list_headroom" {
  description = "Spare entries added to each managed prefix list's max_entries so routine range changes do not force a replacement. NOTE: AWS charges max_entries (not current entries) against the rule quota of every security group referencing the list."
  type        = number
  default     = 8
}

variable "tags" {
  description = "Additional tags applied to every ColorTokens-managed resource."
  type        = map(string)
  default     = {}
}

# ---- Demo / offline plan -----------------------------------------------------

variable "demo_mode" {
  description = "true = configure the AWS provider for offline `terraform plan` against the local stand-in API (no AWS credentials used). Set false for real use."
  type        = bool
  default     = false
}

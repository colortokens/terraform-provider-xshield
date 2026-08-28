variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Workload name."
  type        = string
  default     = "pci-db-01"
}

# ---- org tagging standard (the ColorTokens join key) -------------------------

variable "environment" {
  type    = string
  default = "prod"
}

variable "application" {
  type    = string
  default = "pci"
}

variable "tier" {
  type    = string
  default = "db"
}

variable "additional_tags" {
  type    = map(string)
  default = {}
}

# ---- workload placement ------------------------------------------------------

variable "ami_id" {
  type    = string
  default = "ami-00000000000000000"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "subnet_id" {
  type    = string
  default = null
}

variable "base_security_group_ids" {
  description = "The workload's own security groups; ColorTokens groups are concatenated onto these."
  type        = list(string)
  default     = []
}

variable "demo_mode" {
  description = "true = offline plan without AWS credentials."
  type        = bool
  default     = false
}

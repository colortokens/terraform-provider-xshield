variable "xshield_changes" {
  description = "The account and region's xshield_aws_security_group_changes data source, read once in the root module and passed to every group's module."
  type = object({
    cloud_account_id = string
    region           = string
    groups           = map(set(string))
  })
}

variable "vpc_id" {
  description = "The group's VPC. It may be a VPC the same configuration creates."
  type        = string
}

variable "group_name" {
  description = "The group's name, as the group's own resource sets it."
  type        = string
}

variable "security_group_id" {
  description = "The group the rules belong to. It may be a group the same configuration creates."
  type        = string
}

variable "ingress_rules" {
  description = "Ingress rules keyed by a stable name, with the arguments of aws_vpc_security_group_ingress_rule."
  type = map(object({
    ip_protocol                  = string
    from_port                    = optional(number)
    to_port                      = optional(number)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
    description                  = optional(string)
    tags                         = optional(map(string))
  }))
  default = {}
}

variable "egress_rules" {
  description = "Egress rules keyed by a stable name, with the arguments of aws_vpc_security_group_egress_rule."
  type = map(object({
    ip_protocol                  = string
    from_port                    = optional(number)
    to_port                      = optional(number)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
    description                  = optional(string)
    tags                         = optional(map(string))
  }))
  default = {}
}

variable "fail_on_unacknowledged_carriers" {
  description = "Fail the plan, rather than warn, while Xshield names a resource that carries the group, that it does not enforce on, and that nobody acknowledged when the change was approved."
  type        = bool
  default     = false
  nullable    = false
}

variable "handle" {
  description = "The resource's kind and name: rds/<DB instance identifier>, rds-cluster/<cluster identifier>, lambda/<function name>, flink/<application name>, apprunner/<service name> or asg/<Auto Scaling group name>. An RDS identifier may be given in any case."
  type        = string
}

variable "own_security_group_ids" {
  description = "The resource's own security group IDs, which it carries beside Xshield's. When given, the plan fails if together they are more than AWS allows on the resource, rather than AWS failing the apply. Leave null to skip the check."
  type        = list(string)
  default     = null
}

variable "directory_prefix" {
  description = "SSM path the enforcement workspace writes the directory under."
  type        = string
  default     = "/colortokens/v1"
}

variable "warn_when_unlisted" {
  description = "Warn on every plan while Xshield lists no entry for the resource, to find a handle that names a resource Xshield does not know. Off by default, as a resource Xshield gives nothing to attach has no entry either."
  type        = bool
  default     = false
}

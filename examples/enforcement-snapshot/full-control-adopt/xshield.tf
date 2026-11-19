# What the team adds for Full control, as in ../full-control/xshield.tf: the
# provider, and the one read of the groups an approved change applies to, passed
# to every group's module block.

provider "xshield" {}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
}

output "xshield_review" {
  description = "What Xshield takes out of this workspace's security groups, in words. Empty while no approved change applies to them."
  value       = concat(module.web_rules.review, module.app_rules.review, module.batch_rules.review)
}

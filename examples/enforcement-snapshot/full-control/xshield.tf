# Everything the web team adds for Full control. Unlike a workspace that only
# looks a group up, this one reads Xshield, so it needs the provider and an API
# key whose user can read cloud snapshots, in the XSHIELD_* environment
# variables. After that, a change reaches the group with no edit to this
# workspace:
#
#   1. A change that narrows a rule of the group is approved in Xshield.
#   2. xshield_aws_security_group_changes lists the group, by its name and its
#      VPC. Until it does, the group plans exactly as main.tf declares it.
#   3. module.web_rules then passes the declared rules to
#      xshield_aws_security_group_rules. Xshield finds the rule it narrows by
#      what the rule allows: its direction, protocol, ports and source or
#      destination, whatever its key. It returns the declared rules without
#      that one, once every workload that still needs it carries a ct-cohort-
#      group, which the enforcement workspace creates.
#   4. The next plan of this workspace destroys that rule, and the
#      xshield_review output says why.

provider "xshield" {}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Read once in a workspace, and passed to the module block of every group.
data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
}

output "xshield_review" {
  description = "What Xshield takes out of this workspace's security groups, in words. Empty while no approved change applies to them."
  value       = module.web_rules.review
}

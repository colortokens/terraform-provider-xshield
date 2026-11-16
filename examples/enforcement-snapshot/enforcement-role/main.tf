# The role the enforcement workspace assumes, created once per account by
# whoever owns IAM there. ColorTokens never holds it. It grants security group,
# interface attachment, network ACL entry and directory writes only: no compute,
# IAM or data access. It changes only groups and rules tagged ManagedBy =
# ColorTokens, the tag the enforcement module gives everything it creates. A
# network ACL entry cannot be tagged, so its writes are limited by network ACL.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "pipeline_principal_arns" {
  description = "Identities your Terraform runner uses to assume the role."
  type        = list(string)
}

variable "network_acl_arns" {
  description = "Network ACLs the role may add entries to and remove them from, for the malicious IP block template's addresses. Every network ACL in the account by default; list the ACLs in front of your workloads to narrow it."
  type        = list(string)
  default     = null

  validation {
    condition     = var.network_acl_arns == null || length(coalesce(var.network_acl_arns, [])) > 0
    error_message = "network_acl_arns lists no network ACL, which leaves the role unable to block any address: leave it unset for every network ACL in the account, or list the ones in front of your workloads."
  }
}

data "aws_caller_identity" "current" {}

locals {
  ec2 = "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}"
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.pipeline_principal_arns
    }
  }
}

data "aws_iam_policy_document" "enforcement" {
  # Describe calls cannot be limited to tagged resources. Deleting a group also
  # lists the interfaces that still reference it.
  statement {
    sid       = "Read"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:DescribeNetworkInterfaces", "ec2:DescribeNetworkAcls"]
    resources = ["*"]
  }

  statement {
    sid       = "CreateGroupsInVpcs"
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["${local.ec2}:vpc/*"]
  }

  statement {
    sid       = "CreateOwnGroups"
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["${local.ec2}:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/ManagedBy"
      values   = ["ColorTokens"]
    }
  }

  statement {
    sid       = "TagWhatItCreates"
    actions   = ["ec2:CreateTags"]
    resources = ["${local.ec2}:security-group/*", "${local.ec2}:security-group-rule/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSecurityGroup", "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"]
    }
  }

  # A rule action also authorizes the group it belongs to, so the group's tag
  # decides which rules the role can change.
  statement {
    sid = "ChangeOwnGroups"
    actions = [
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]
    resources = ["${local.ec2}:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ManagedBy"
      values   = ["ColorTokens"]
    }
  }

  statement {
    sid = "RulesOfOwnGroups"
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
    ]
    resources = ["${local.ec2}:security-group-rule/*"]
  }

  statement {
    sid       = "TagOwnRules"
    actions   = ["ec2:CreateTags", "ec2:DeleteTags"]
    resources = ["${local.ec2}:security-group-rule/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ManagedBy"
      values   = ["ColorTokens"]
    }
  }

  # The request carries the interface's other groups too, so it cannot be
  # limited to tagged groups.
  statement {
    sid       = "InstanceAttachments"
    actions   = ["ec2:ModifyNetworkInterfaceAttribute"]
    resources = ["${local.ec2}:network-interface/*", "${local.ec2}:security-group/*"]
  }

  # The module only creates and deletes entries, at the rule numbers Xshield gives it; it never replaces one.
  statement {
    sid       = "NetworkACLEntries"
    actions   = ["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry"]
    resources = coalesce(var.network_acl_arns, ["${local.ec2}:network-acl/*"])
  }

  statement {
    sid = "ResourceDirectory"
    actions = [
      "ssm:PutParameter",
      "ssm:DeleteParameter",
      "ssm:GetParameter",
      "ssm:GetParametersByPath",
      "ssm:AddTagsToResource",
      "ssm:RemoveTagsFromResource",
      "ssm:ListTagsForResource",
    ]
    resources = ["arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/colortokens/*"]
  }

  # Terraform reads every parameter's metadata after writing it; this action
  # takes no parameter ARN.
  statement {
    sid       = "ResourceDirectoryMetadata"
    actions   = ["ssm:DescribeParameters"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "enforcement" {
  name               = "xshield-enforcement"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role_policy" "enforcement" {
  name   = "xshield-enforcement"
  role   = aws_iam_role.enforcement.id
  policy = data.aws_iam_policy_document.enforcement.json
}

output "enforcement_role_arn" {
  description = "Pass this to the enforcement workspace as enforcement_role_arn."
  value       = aws_iam_role.enforcement.arn
}

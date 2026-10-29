# The role the enforcement workspace assumes, created once per account by
# whoever owns IAM there. ColorTokens never holds it. It grants security group,
# interface attachment and directory writes only: no compute, IAM or data access.

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
  statement {
    sid = "SecurityGroupsAndRules"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
      "ec2:CreateTags",
      "ec2:Describe*",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "InstanceAttachments"
    actions   = ["ec2:ModifyNetworkInterfaceAttribute"]
    resources = ["*"]
  }

  statement {
    sid = "ResourceDirectory"
    actions = [
      "ssm:PutParameter",
      "ssm:DeleteParameter",
      "ssm:GetParameter*",
      "ssm:AddTagsToResource",
      "ssm:ListTagsForResource",
    ]
    resources = ["arn:aws:ssm:*:*:parameter/colortokens/*"]
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

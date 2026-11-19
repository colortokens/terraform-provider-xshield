# terraform test, offline: which network ACLs the role may add the malicious IP block template's entries to.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

variables {
  pipeline_principal_arns = ["arn:aws:iam::123456789012:role/runner"]
}

run "every_network_acl_of_the_account_by_default" {
  command = plan

  assert {
    condition     = one([for s in data.aws_iam_policy_document.enforcement.statement : s.resources if s.sid == "NetworkACLEntries"]) == toset(["arn:aws:ec2:*:123456789012:network-acl/*"])
    error_message = "the role adds and removes entries on every network ACL of the account"
  }
  assert {
    condition     = one([for s in data.aws_iam_policy_document.enforcement.statement : s.actions if s.sid == "NetworkACLEntries"]) == toset(["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry"])
    error_message = "the role only creates and deletes entries, never replaces one"
  }
}

run "only_the_listed_network_acls" {
  command = plan

  variables {
    network_acl_arns = ["arn:aws:ec2:us-east-1:123456789012:network-acl/acl-0a1b"]
  }

  assert {
    condition     = one([for s in data.aws_iam_policy_document.enforcement.statement : s.resources if s.sid == "NetworkACLEntries"]) == toset(["arn:aws:ec2:us-east-1:123456789012:network-acl/acl-0a1b"])
    error_message = "the role adds and removes entries only on the listed network ACLs"
  }
}

run "an_empty_list_is_refused" {
  command = plan

  variables {
    network_acl_arns = []
  }

  expect_failures = [var.network_acl_arns]
}

# aws enforcement module

Applies the AWS resources Xshield rendered for one account and region, and reports the apply to Xshield.

```hcl
module "xshield_enforcement" {
  source = "colortokens/enforcement/xshield//modules/aws"
}
```

It creates, from `xshield_enforcement_snapshot`:

- one `aws_security_group` per workload, named and tagged as the Xshield cloud connector names its own, so the connector recognises it;
- one `aws_vpc_security_group_ingress_rule` or `_egress_rule` per rule;
- one `aws_network_interface_sg_attachment` per instance interface, which adds the group and keeps the interface's other groups;
- one `aws_ssm_parameter` per database, function or service, read by the `group-lookup` module;
- the `xshield_enforcement_receipt` that tells Xshield what was applied.

While Xshield has published nothing for the account and region, it creates nothing, not even the receipt, and the plan shows no change. If the account already holds security groups Xshield rendered for a pipeline, the plan fails instead: Xshield never unpublishes an account, so that means the provider is reading another tenant or endpoint, and applying would remove them. The check reads groups with `ec2:DescribeSecurityGroups`.

Resource keys are instance IDs and handles, so a plan names the workload each change is for.

## Inputs

| Name | Default | Description |
|--|--|--|
| `cloud_account_id` | The AWS provider's account | AWS account to enforce. A snapshot for any other account is refused. |
| `region` | The AWS provider's region | AWS region to enforce. |
| `snapshot_version` | `null` | Pins a version for break-glass rollback. Xshield reports the account as pending while it is set. |
| `workspace` | `xshield-enforcement-<account>-<region>` | Name Xshield shows for the workspace that applied a version. |
| `tags` | `{}` | Added to every resource. `ManagedBy` and `ct:*` are reserved. |

## Outputs

| Name | Description |
|--|--|
| `published` | False while Xshield has published nothing for the account and region. |
| `version` | Snapshot version applied. Null while nothing is published. |
| `summary` | Counts of groups, rules and attachments, the handles owning workspaces attach, and groups being withdrawn. |
| `security_group_ids` | Each Xshield asset's group ID, keyed by Xshield asset ID. |
| `directory` | The SSM parameter each owning workspace reads, keyed by handle. |

Requires Terraform 1.7 and the AWS provider 6 or later. `terraform test` runs the tests in `tests/` offline, with both providers mocked.

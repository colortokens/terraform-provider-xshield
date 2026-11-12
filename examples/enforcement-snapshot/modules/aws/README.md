# aws enforcement module

Applies the AWS resources Xshield rendered for one account and region, and reports the apply to Xshield.

```hcl
module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws?ref=vX.Y.Z"
}
```

It creates, from `xshield_aws_enforcement_snapshot`:

- one `aws_security_group` per workload, named and tagged as the Xshield cloud connector names its own, so the connector recognises it;
- one `aws_vpc_security_group_ingress_rule` or `_egress_rule` per rule;
- one `aws_network_interface_sg_attachment` per instance interface, which adds the group and keeps the interface's other groups;
- one `aws_ssm_parameter` per database, function or service, read by the `aws-group-lookup` module;
- the `xshield_enforcement_receipt` that tells Xshield what was applied.

While Xshield has published nothing for the account and region, it creates nothing, not even the receipt, and the plan shows no change. The run then warns, through the `xshield_published` check, that nothing is published and says what to look at if the account should have policy. If the account already holds security groups Xshield rendered for a pipeline, the plan fails instead: Xshield never unpublishes an account, so that means the provider is reading another tenant or endpoint, and applying would remove them. The check reads groups with `ec2:DescribeSecurityGroups`.

To stop enforcing, withdraw the policy in Xshield. Xshield then publishes a version without the groups, and the next apply removes them and still sends the receipt, so Xshield knows the removal was applied. Do not run `terraform destroy`, or remove the module block, to stop enforcing: both delete the groups and tell Xshield nothing. See [Stop enforcing](../../README.md#stop-enforcing).

An interface that filled up since Xshield last discovered it cannot take a new group, and AWS would refuse the apply. So an attachment neither the last receipt holds nor a hand-over offers goes only on an interface with room for every new group, against the limit Xshield discovered. Any other is left out with a warning naming the interface and its instance, the receipt leaves it out, and Xshield refuses the workload once discovery shows the interface full. A new group the interface already carries takes no further room: an apply that attached it and then failed sent no receipt, and the run after it keeps the attachment. Only those interfaces and groups are read, with `ec2:DescribeNetworkInterfaces` and `ec2:DescribeSecurityGroups`.

A group's new rules are created before its old ones are removed, as the cloud connector writes them, so access a change keeps holds throughout the apply, and a rule AWS refuses leaves the old rules in place. While it changes, a group holds its old and new rules at once. When that would take it past the account's quota of rules per security group but its new rules alone fit, the apply first removes the old rules no new rule replaces, and the next apply adds the new ones: access both versions allow holds throughout, while a port the change moves closes on its old number one apply before it opens on its new one. A change that does not fit even then leaves the group as last applied. Either way Xshield says so in a `groupRefused` notice of `xshield_enforcement_status`, with how many rules past the quota the group would be. To make such a change in one apply, first remove rules from the policy that the change does not replace, and apply that, or raise the quota. A rule naming another workload's Xshield group counts once in each address family and comes out only once the new rules are in, so when that workload stops carrying its group while this one is at the quota, the group stays on that workload, without rules, until the change fits: the notice names that group, and the group's `withdrawing` notice points back to it.

Resource keys are instance IDs and handles, so a plan names the workload each change is for.

## Reading a change in words

The `review` output says what the applied version holds, as a list of sentences. A plan shows only a root module's outputs, so export it from the root module:

```hcl
output "xshield_review" {
  value = module.xshield_enforcement.review
}
```

A plan then lists the sentences that change under `Changes to Outputs`. Here a change set adds a cohort group, and one rule's source narrows:

```
Changes to Outputs:
  ~ xshield_review = [
      + "Cohort group ct-cohort-0example is for i-0a1 and i-0b2. It keeps access that customer group sg-0example gives up under change set cs-example.",
      + "Cohort group ct-cohort-0example allows all TCP except 80 from 10.20.0.0/16.",
        "Group for i-0a1 is attached by this workspace to 1 network interface.",
      - "Group for i-0a1 allows TCP 443 from 0.0.0.0/0 and ::/0 (template Web servers).",
      + "Group for i-0a1 allows TCP 443 from 10.0.0.0/8 (template Web servers).",
        "Group for i-0b2 is attached by this workspace to 1 network interface.",
        # (2 unchanged elements hidden)
        "Group for rds/orders-db allows TCP 5432 from 10.20.1.11/32 (template Databases).",
      - "Version 8c2f41d09a3b holds 3 groups, 4 rules and 2 interface attachments for 111111111111/us-east-1.",
      + "Version e91b0c55d2f4 holds 4 groups, 5 rules and 4 interface attachments for 111111111111/us-east-1.",
    ]
```

Every sentence names its group, so it reads on its own when the plan hides the others.

- The first sentence for a group says whose it is and who attaches it. A workload is named by its instance ID or its handle, which is the only name the snapshot holds for it. A cohort group names the workloads it is for, the ID of the customer group whose access it keeps, and the change set. A group being withdrawn says so.
- Then comes one sentence for each set of ports the group allows: `from` its sources for ingress rules, `to` its destinations for egress rules. Ports read as `TCP 22`, `TCP 8000-8100`, `TCP 22, 80 and 443`, `all TCP`, or `all traffic` for every protocol. Ranges that run from port 0 to port 65535 and leave ports out between them read by what they leave out: 0-79 with 81-65535 is `all TCP except 80`.
- A sentence names the rules' template in brackets, taken from the end of each rule's description. A rule that a workload's own group keeps for a change set names the customer group and the change set instead.
- The last sentence counts the groups, rules and interface attachments. It starts with the first twelve characters of the version, so anything that changes the version changes at least that sentence.

Two limits keep the output short enough to read. A sentence names five sources, destinations or workloads and counts the rest. The output describes `review_max_groups` groups, 50 unless you set it: cohort groups first, then the rest in key order. One sentence counts the groups past that number. A change these limits hide still changes the last sentence, and the plan's resource changes show it in full.

While Xshield has published nothing, the output is one sentence that says so. For a version that holds nothing, it is the last sentence alone.

## Inputs

| Name | Default | Description |
|--|--|--|
| `cloud_account_id` | The AWS provider's account | AWS account to enforce. A snapshot for any other account is refused. |
| `region` | The AWS provider's region | AWS region to enforce. |
| `snapshot_version` | `null` | Pins a version for break-glass rollback. Xshield reports the account as pending while it is set. |
| `workspace` | `xshield-enforcement-<account>-<region>` | Name Xshield shows for the workspace that applied a version. |
| `tags` | `{}` | Added to every resource. `ManagedBy` and `ct:*` are reserved. |
| `review_max_groups` | `50` | How many groups the `review` output describes in words. Groups past this number are counted, not described. |

## Outputs

| Name | Description |
|--|--|
| `published` | False while Xshield has published nothing for the account and region. |
| `version` | Snapshot version applied. Null while nothing is published. |
| `summary` | Counts of groups, rules and attachments, the handles owning workspaces attach, and groups being withdrawn. |
| `review` | What the applied version holds, as sentences: whose each group is, what its rules allow, and a closing count. |
| `security_group_ids` | Each Xshield asset's group ID, keyed by Xshield asset ID. |
| `directory` | The SSM parameter each owning workspace reads, keyed by handle. |

Requires Terraform 1.7 and the AWS provider 6 or later. `terraform test` runs the tests in `tests/` offline, with both providers mocked.

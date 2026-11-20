# aws enforcement module

Applies the AWS resources Xshield rendered for one account and region, and reports the apply to Xshield.

```hcl
module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws?ref=v26.4.1"
}
```

It creates, from `xshield_aws_enforcement_snapshot`:

- one `aws_security_group` per workload, named as [Group names](#group-names) describes and tagged as the Xshield cloud connector tags its own;
- one `aws_vpc_security_group_ingress_rule` or `_egress_rule` per rule;
- one `aws_vpc_security_group_rules_exclusive` per group, naming exactly that group's rules, so the next apply removes a rule added to the group outside Terraform;
- one `aws_network_interface_sg_attachment` per instance interface, which adds the group and keeps the interface's other groups;
- one `aws_ssm_parameter` per database, function or service, read by the `aws-group-lookup` module;
- one `aws_network_acl_rule` per address of the malicious IP block template, which denies all traffic from it inbound or to it outbound on the network ACL in front of the workloads the template is assigned to;
- the `xshield_aws_enforcement_receipt` that tells Xshield what was applied.

While Xshield has published nothing for the account and region, it creates nothing, not even the receipt, and the run warns through the `xshield_published` check. If the account already holds security groups Xshield rendered for a pipeline, the plan fails instead, as the provider is most likely reading another tenant and applying would remove them.

To stop enforcing, withdraw the policy in Xshield and keep running the module: the next apply removes the groups and still sends the receipt. Do not run `terraform destroy`, or remove the module block: both delete the groups and tell Xshield nothing.

Each group holds only the rules the snapshot declares for it, so the next apply removes a rule added outside Terraform. Set `enable_exclusive_rules = false` to leave such rules until a person removes them. Security groups of your own are never managed this way.

A change is applied so that access it keeps holds throughout: new rules and attachments go in before old ones come out, and an attachment goes only on an interface with room for it. Where AWS quotas or a full interface stop a change, the plan or `xshield_aws_enforcement_status` says what and why. Network ACL entries are numbered in front of the allows that cover their address; write no entry of your own at a rule number Xshield holds. The [Xshield documentation](https://docs.xshield.colortokens.com/developer-tools/terraform/pipeline-delivery-aws-reference#how-the-enforcement-module-applies-a-change) covers these behaviours in depth.

Resource keys are instance IDs and handles, and `<network ACL ID>/<in|out>/<address>` for a network ACL entry, so a plan names the workload or the address each change is for.

## Group names

A group takes the name the snapshot gives it. When the account has no security group name template in Xshield, that is the name the Xshield cloud connector gives its own: `ct-policy-` and twelve hexadecimal characters for a workload's group, `ct-cohort-` and sixteen for a cohort group. When the account has a template, Xshield names each new group from it:

| Token | Value |
|--|--|
| `{id}` | The digest that tells Xshield's groups apart: twelve hexadecimal characters for a workload's group, sixteen for a cohort group. Required, exactly once. |
| `{kind}` | `policy` for a workload's group, `cohort` for a cohort group. |
| `{region}` | The AWS region. |
| `{asset}` | The workload's name in Xshield; for the group of an Auto Scaling group or an Aurora cluster, that group's or cluster's own name; for a cohort group, the name of the customer group whose access it keeps. |
| `{tag:<key>}` | The value of the workload's AWS tag `<key>`; empty for a cohort group. |

Text outside the tokens may use only the characters a security group name can hold, and the template must start with text or with `{id}`, `{kind}` or `{region}`, never with `sg-`, and come to at most 255 characters with every token at its longest, so Xshield refuses a template that could give a name AWS refuses. A character a security group name cannot hold becomes `-` in a token's value, which is cut at 64 characters. With a template, a group's `Name` tag is its name. For example, `xs-{kind}-{asset}-{id}` names the group of a database named `orders-db` `xs-policy-orders-db-` followed by its digest.

A group keeps its name for as long as it exists, since AWS replaces a group to rename it: setting, changing or removing the template names only groups created after the change. Xshield refuses to move an account to connector delivery while it has a template. If a group of another owner already has a name the template gives, the plan stops before anything is applied and names that group and its VPC.

The template names groups only. Add tags of your own through the `tags` input or the AWS provider's `default_tags`; the snapshot's own tags, `Name` among them, take precedence over both.

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
- One sentence for each address a network ACL blocks, such as `Network ACL acl-0a1b denies all inbound traffic from 203.0.113.7/32, which the malicious IP block template blocks.`
- The last sentence counts the groups, rules and interface attachments, and the network ACL entries when there are any. It starts with the first twelve characters of the version, so anything that changes the version changes at least that sentence.

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
| `enable_exclusive_rules` | `true` | Each group this module creates holds only the rules the snapshot declares, so the next apply removes a rule added outside Terraform. Set `false` to leave such a rule until a person removes it. |
| `review_max_groups` | `50` | How many groups the `review` output describes in words. Groups past this number are counted, not described. |

## Outputs

| Name | Description |
|--|--|
| `published` | False while Xshield has published nothing for the account and region. |
| `version` | Snapshot version applied. Null while nothing is published. |
| `exclusive_rules_enabled` | Whether each group this module creates holds only the rules the snapshot declares. The receipt tells Xshield the same. |
| `summary` | Counts of groups, rules, attachments and network ACL entries, the handles owning workspaces attach, and groups being withdrawn. |
| `review` | What the applied version holds, as sentences: whose each group is, what its rules allow, and a closing count. |
| `security_group_ids` | Each Xshield asset's group ID, keyed by Xshield asset ID. |
| `attachment_keys` | The interface attachments this run declares, by snapshot key: the snapshot's, less any whose interface no longer exists or has no room. The import blocks in `recovery/` and `handover/` import only these. |
| `network_acl_entry_keys` | The network ACL entries this run declares, by snapshot key: the snapshot's, less, while `snapshot_version` pins a version, any on a network ACL that no longer exists. The import blocks in `recovery/` import only these. |
| `directory_entries` | The SSM parameter each owning workspace reads, keyed by handle. |

Requires Terraform 1.7 and the AWS provider 6.29.0 or later, the first release with `aws_vpc_security_group_rules_exclusive`. `terraform test` runs the tests in `tests/` offline, with both providers mocked.

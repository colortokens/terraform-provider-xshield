# Pipeline-rendered enforcement for AWS

Apply Xshield segmentation policy through your own Terraform pipeline. Xshield renders every rule; these modules create exactly what it lists, and report back what was applied.

To set it up, follow the [step-by-step guide](../../docs/guides/aws-pipeline-enforcement.md). This page is the reference behind it: why each step is needed, what each message means, and how to recover from each failure.

## Who writes what

Xshield decides everything that is enforced: which groups exist, every rule in them, what carries each group, which addresses of the malicious IP block template each network ACL denies, and under Full control which rule of a group of your own is left out. None of that is written in your code. Your code carries it to AWS, through the modules below.

**Shipped with the provider.** You write none of it. The modules live in the [`modules/`](../../modules/) directory at the root of the provider's repository. Call each module by its `source`, at the tag of the provider release you run. The modules use the provider's own data sources and receipt resource, which the [provider's README](../../README.md#enforcing-aws-policy-through-your-own-pipeline) lists.

| Directory | What it is |
|--|--|
| [`modules/aws`](../../modules/aws/) | The enforcement module. One block per AWS account and region. |
| [`modules/aws-group-lookup`](../../modules/aws-group-lookup/) | Gives a database, function or service the group it must attach. Reads only SSM. |
| [`modules/aws-security-group-rules`](../../modules/aws-security-group-rules/) | Declares one of your own security group's rules through Full control. A group no approved change applies to plans as its code declares it. |

**To copy and fill in.** New code in your repository, complete but for its inputs.

| Directory | What it is |
|--|--|
| `enforcement/` | An enforcement workspace, ready to copy. |
| `enforcement-role/` | The role the enforcement workspace assumes, with only the permissions below. |
| `monitor/` | A workspace that reports each enforcement problem as a named check, and stops a plan on the ones you choose. |
| `chain/` | A GitHub Actions workflow that runs the owners' workspaces after the enforcement workspace, in order, on a schedule. The same order adds a group and, once policy stops using it, removes it. |
| `policies/` | One example policy, `xshield-checks`, for the workspace that runs the monitor. It reports every failed Xshield check of a plan, for Sentinel and for OPA. |

**Files for one apply.** Each goes into the enforcement workspace when the event it names happens, and is deleted afterwards.

| Directory | What it is |
|--|--|
| `recovery/` | Import blocks that rebuild a lost enforcement state from the last receipt. |
| `handover/` | Import blocks that take over the groups the cloud connector created, when an account moves to pipeline delivery. |
| `leave/` | A `removed` block that hands the account's groups to the cloud connector, when an account moves back to connector delivery. |

**Stand-ins for workspaces you already have.** Do not copy these. Each shows a team's own workspace after the change Xshield needs: `xshield.tf` holds everything the team adds, and `main.tf` is the team's own code with each line changed for Xshield marked.

| Directory | What it is |
|--|--|
| `database/` | A workspace that owns an RDS instance and attaches the group Xshield gave it beside its own. It declares none of Xshield's rules. |
| `function/` | A workspace that owns a Lambda function in a VPC and attaches the group Xshield gave it beside its own, and gives it up again when policy stops using it. |
| `apprunner/` | A workspace that owns an App Runner service, with a VPC connector of its own that carries the group Xshield gave it beside its own. |
| `full-control/` | A workspace that owns a security group Xshield narrows under Full control, and declares the group's rules through `modules/aws-security-group-rules`. |

**Another way to deliver.**

| Directory | What it is |
|--|--|
| `connector-managed/` | The other way: author policy in HCL and let the Xshield connector enforce it. |

### What a person does

| Where | What a person does | How often |
|--|--|--|
| A new enforcement workspace | Copies `enforcement/`, creates its role from `enforcement-role/`, sets the API key on the runner, applies it and checks each workload, then runs it on a schedule: step 1. Where the cloud connector enforces the account today, adds `handover/handover.tf` for the first apply, then deletes it. | Once for each account and region |
| The workspace that owns a database, function or service | Adds the lookup module and puts its output in the resource's list of groups: step 2. Where the cloud connector enforces the account today, only once the first enforcement apply has succeeded. | Once for each resource |
| A workspace that declares an instance's or an interface's security groups | Adds `ignore_changes`, before the enforcement workspace's first apply: step 3. | Once for each such instance or interface |
| Under Full control, the workspace that owns a security group Xshield narrows | Configures the `xshield` provider and moves the group's rules into the rules module: step 4. | Once for each group |
| A new monitor workspace | Copies `monitor/` and runs it on a schedule: step 5. | Once for each account and region |
| The pipeline that runs the workspaces | Runs the workspaces from steps 2 and 4 after the enforcement workspace: step 6. | Once |

After that, a policy change approved in Xshield needs no edit to any of this code. It reaches AWS on the next run of the enforcement workspace. It also needs the next run of an owning workspace when it changes which groups a resource of that workspace carries, or leaves out a rule of a group that workspace owns: step 6 runs those after the enforcement workspace.

## Quickstart

### 1. Enforcement workspace: one per account and region

```hcl
provider "aws" {
  region = "us-east-1"
  assume_role { role_arn = "arn:aws:iam::123456789012:role/xshield-enforcement" }
}

provider "xshield" {} # credentials from XSHIELD_* environment variables

module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws?ref=v0.2.0"
}
```

The modules ship in the provider's repository, under `modules/`. Every `ref` on this page is the provider release it was published with; keep it at the tag of the provider release you run, so the module and the provider match. `enforcement/` calls the module as `../../../modules/aws`, which exists only inside this repository: in your copy, change that `source` to the address above, or `terraform init` cannot find the module.

The module needs no inputs. It enforces the account and region the AWS provider is configured for, and refuses to apply a snapshot meant for any other. Each plan names the workload every change is for:

```
# module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this["rds/orders-db/in/tcp/5432/10.20.1.11/32"] will be created
# module.xshield_enforcement.aws_network_interface_sg_attachment.this["i-0a1b2c3d/eni-0f9e8d7c"] will be created
```

Set the API key as secret environment variables on the runner. `XSHIELD_PRIVATE_KEY` takes the key itself, so no file is needed:

| Variable | Value |
|--|--|
| `XSHIELD_SERVER_URL` | `https://<tenant>.colortokens.com` |
| `XSHIELD_TENANCY_ID`, `XSHIELD_USER_ID`, `XSHIELD_FINGERPRINT` | Shown with the API key under **Settings > API Keys** |
| `XSHIELD_PRIVATE_KEY` | The PEM private key itself |
| or `XSHIELD_PRIVATE_KEY_PATH` | The path to a file holding it, never the key: the provider refuses a key given here |

The role the workspace assumes needs only these actions; `enforcement-role/` creates it, limiting every group and rule change to resources tagged `ManagedBy = ColorTokens`. A network ACL entry cannot be tagged, so its changes are limited by network ACL instead: every network ACL in the account, or only those you list in `network_acl_arns`:

| Purpose | Actions |
|--|--|
| Groups and rules | `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupEgress`, `ec2:RevokeSecurityGroupIngress`, `ec2:RevokeSecurityGroupEgress`, `ec2:ModifySecurityGroupRules`, `ec2:CreateTags`, `ec2:DeleteTags` |
| Instance attachments | `ec2:ModifyNetworkInterfaceAttribute` |
| Malicious IP block | `ec2:CreateNetworkAclEntry`, `ec2:DeleteNetworkAclEntry` |
| Reads | `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeNetworkAcls` |
| Directory | `ssm:PutParameter`, `ssm:DeleteParameter`, `ssm:GetParameter`, `ssm:GetParametersByPath`, `ssm:AddTagsToResource`, `ssm:RemoveTagsFromResource`, `ssm:ListTagsForResource` on `arn:aws:ssm:*:*:parameter/colortokens/*`, and `ssm:DescribeParameters`, which takes no parameter ARN |

Deleting a group that an AWS-managed interface still references, such as one Lambda has not yet removed, fails until AWS removes that interface; the next apply then succeeds. Grant `ec2:DetachNetworkInterface` and `ec2:DeleteNetworkInterface` if you would rather Terraform removed such interfaces itself.

#### Rules added by hand

Each group the module creates holds only the rules Xshield lists for it. The module declares one `aws_vpc_security_group_rules_exclusive` for each such group, cohort groups included. A rule someone adds to one of these groups outside Terraform shows in the next plan as an in-place change of that resource, and the apply removes it. Deleting that resource from the code revokes no rule.

To leave such rules in place, set `enable_exclusive_rules = false` on the module. A rule added by hand then stays until a person removes it. The module's receipt tells Xshield which you chose, so its drift finding says who removes the rule.

Only the groups Xshield creates are managed this way. Groups of your own are not, including those you declare through `modules/aws-security-group-rules` under Full control.

The module needs the AWS provider 6.29.0 or later, the first release with `aws_vpc_security_group_rules_exclusive`.

The first apply after upgrading to a module that has it adds one such resource for each Xshield group, and removes any rule in those groups that the snapshot does not declare. Its plan shows each new resource with the rules the group keeps, not the rules it removes, and the receipt as an in-place change. To see first what the apply removes, read the monitor's `drift_high` report: each `ruleUnmanaged` finding is such a rule. To decide on them before anything is removed, upgrade with `enable_exclusive_rules = false`, then turn it on. After that first apply, a rule added by hand shows in the plan as a change of its group's resource before anything is removed.

#### Malicious IP block on network ACLs

A security group can only allow traffic. So where the account's protection level blocks on network ACLs, the module blocks the addresses of the malicious IP block template on the network ACL in front of each workload the template is assigned to. Each address is one `aws_network_acl_rule` that denies all traffic from it inbound, or to it outbound:

```
# module.xshield_enforcement.aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"] will be created
```

- **Rule numbers.** AWS applies the lowest-numbered entry that matches, so Xshield numbers each entry in front of every allow on the network ACL that covers its address: one of the even numbers from 50 to 98 where that is in front, otherwise the lowest number free in front. It keeps an entry's number while the entry is in front of those allows. An allow put in front of it lets the address's traffic through until the next apply after the cloud connector observes the allow: that apply writes the deny at a number in front of the allow, then deletes the old entry, so the move itself opens no gap. When no number in front of the allow is free, the traffic keeps passing, and Xshield reports it. An entry changed outside Terraform, or another entry written at an entry's number, is not taken over while the version holds the deny at that number: the plan stops and names it. Once the cloud connector has observed the change, the plan that moves the deny deletes whatever AWS holds at the old number, as [When something goes wrong](#when-something-goes-wrong) describes.
- **Room.** Xshield adds an entry only where the network ACL has room. It counts every rule of the network ACL in that direction against the account's quota of rules per network ACL, AWS's default rules included, and leaves two places free for your own. An address that does not fit is not written, and the plan and apply go ahead without it: Xshield names the network ACL and the addresses in a `networkAclEntryRefused` notice, and the monitor reports `network_acl_block_not_enforced`. The count is the cloud connector's last observation, so when more rules than those two places are added in the meantime, AWS refuses an entry with `NetworkAclEntryLimitExceeded`: see [When something goes wrong](#when-something-goes-wrong).
- **Changes in AWS.** An entry changed or deleted outside Terraform is drift of high severity. The next apply creates a deleted entry again. AWS holds one entry for each rule number and direction, and Terraform deletes an entry by its number alone, so an entry changed in place, or another entry written at a deleted entry's number, is not taken over while the version holds the deny at that number: the next plan stops before anything is applied and names it. Once you remove it from the state and the cloud connector observes the change, Xshield gives the deny another number in front of the allows that cover its address, and the next apply writes it there. If the cloud connector observes the change before an enforcement plan runs, that plan writes the deny at its new number and then deletes the entry at the old number, whatever it holds. Nothing checks an entry the version no longer holds either: when an address leaves the template, the template is unassigned or the policy is undeployed, the apply deletes the entry at the address's number, whatever it holds. So write no entry of your own at a number Xshield holds, and before you apply such a plan, check that each entry it deletes is still Xshield's deny: `aws ec2 describe-network-acls --network-acl-ids <network ACL ID> --query 'NetworkAcls[].Entries'`. Run `terraform state rm` on any that is not, and the apply leaves it in place. A key whose old number the plan shows as a deposed object, `(deposed object …) will be destroyed`, is one an apply moved and stopped before deleting the old entry, and each such apply leaves one more. `terraform state rm` on the key takes any deny at its new number and every deposed number out of state, so note them all first: the new number from `terraform state show` on the key, when it shows one, and each deposed number from the plan, or from `terraform show -json` as [leave/leave.tf](leave/leave.tf) lists them. After the `terraform state rm`, check the entry at each noted number. While the version holds the key and the entry at the new number is still the deny, import it back to the key, with ID `<network ACL ID>:<new number>:-1:<egress>`, as [An interrupted apply](#an-interrupted-apply) shows, and delete by hand each other noted entry that is still the deny, as the new one blocks everything they did. While the version holds the key and the entry at the new number is not the deny, or there is none, keep the other noted entries that are still the deny: they are what blocks the address until the apply that writes the deny at its next number, and you delete them by hand once that apply has run. Once the version no longer holds the key, delete by hand each noted entry that is still the deny, the one at the new number included. Delete with `aws ec2 delete-network-acl-entry --network-acl-id <network ACL ID> --rule-number <number> --ingress`, or `--egress` for an outbound entry. Leave any entry that is not the deny.
- **Reach.** AWS applies a network ACL to every resource in the subnets associated with it, so an entry blocks its address for all of them: workloads the template is not assigned to, and resources Xshield does not enforce on, such as a NAT gateway or a load balancer. Once the cloud connector has observed the network ACL, Xshield names those subnets and workloads in a `networkAclReach` notice, and the plan's `xshield_review` output repeats it while it is about the version planned. Nothing is refused for it. To block the addresses for fewer resources, put the template's workloads in subnets with a network ACL of their own.
- **Checked at plan.** A version with network ACL entries reads the region's network ACLs while planning. A role without `ec2:DescribeNetworkAcls`, such as one `enforcement-role/` created before network ACL blocking, stops the plan there with `UnauthorizedOperation`, before anything is applied. So does a network ACL deleted since Xshield planned entries on it, as AWS would refuse them: the plan names it, and goes ahead once the cloud connector observes it gone, since Xshield then plans no entry for it.
- **Upgrading.** Follow [Turning on the malicious IP block](#turning-on-the-malicious-ip-block) before Xshield blocks on any network ACL of the account.

#### Turning on the malicious IP block

For an account that already runs this pipeline. Each step works with what the step before it left, so the pipeline keeps running throughout, and nothing is written to a network ACL before the role can read and write it.

1. **Upgrade the module and the provider together**, to the release that blocks on network ACLs:

   ```hcl
   terraform {
     required_providers {
       aws     = { source = "hashicorp/aws", version = ">= 6.29.0" }
       xshield = { source = "colortokens/xshield", version = "0.2.0" }
     }
   }

   module "xshield_enforcement" {
     source = "github.com/colortokens/terraform-provider-xshield//modules/aws?ref=v0.2.0"
   }
   ```

   While Xshield blocks on no network ACL, the plan shows no network ACL change and the module reads no network ACL, so the role you have still works. Once it blocks on one, an older provider stops the plan with `This provider version cannot apply this snapshot`, and an older module leaves the entries out of its receipt, which Xshield refuses.

2. **Give the role the network ACL actions.** Apply `enforcement-role/` from the same release. Its plan changes the role's policy: it adds `ec2:DescribeNetworkAcls` to the reads, and `ec2:CreateNetworkAclEntry` and `ec2:DeleteNetworkAclEntry` on every network ACL in the account. To allow fewer, list the network ACLs associated with the subnets of the workloads the template may be assigned to:

   ```hcl
   # terraform.tfvars of enforcement-role/
   pipeline_principal_arns = ["arn:aws:iam::123456789012:role/ci-runner"]
   network_acl_arns = [
     "arn:aws:ec2:us-east-1:123456789012:network-acl/acl-0a1b",
   ]
   ```

   The plan cannot see this list, so an entry on a network ACL left out of it fails the apply with `UnauthorizedOperation`. Update the list when such a workload moves to another subnet, or leave it unset. A role of your own needs the Malicious IP block actions and `ec2:DescribeNetworkAcls` from the table above.

3. **Copy `monitor/` again.** It is a copy, not a module, and one copied from an earlier release has no `network_acl_block_not_enforced` check, so it says nothing when an address is not blocked. This release warns on it by default. If you set `warn_on` or `fail_on` yourself, add it there:

   ```hcl
   warn_on = ["drift_high", "drift_medium", "apply_overdue", "network_acl_block_not_enforced"]
   ```

4. **Check the network ACLs in front of your workloads.** For the subnet of each workload the template may be assigned to:

   ```sh
   aws ec2 describe-network-acls --filters Name=association.subnet-id,Values=subnet-0a1b \
     --query 'NetworkAcls[].[NetworkAclId, Entries[].[Egress,RuleNumber,RuleAction,CidrBlock||Ipv6CidrBlock]]' --output text
   ```

   In each direction, Xshield needs a place for each address beside your entries, AWS's default rules and two places it leaves for yours, within the account's quota of rules per network ACL (20 unless raised). It also needs a free rule number in front of every allow that covers the address: one of the even numbers from 50 to 98 when your allows are numbered after them, as the default network ACL's allow at 100 is, otherwise a number below your lowest such allow. Where there is no room or no number, the address is not blocked on that network ACL and the monitor reports it. AWS applies the lowest number that matches, so leave the numbers in front of your allows free rather than numbering an allow of yours 1.

   Then check that no workspace of yours declares these network ACLs' entries as a whole. `aws_default_network_acl`, and `aws_network_acl` with `ingress` or `egress`, hold every entry of the network ACL, so each apply of that workspace deletes Xshield's denies, and the addresses are not blocked until the next enforcement apply writes them again. In that workspace, declare your entries as `aws_network_acl_rule` resources, which hold one entry each, importing each one so that nothing is deleted. On `aws_default_network_acl`, add `ingress` and `egress` to `lifecycle` `ignore_changes` first, as it otherwise deletes every entry it does not declare. On `aws_network_acl`, remove `ingress` and `egress`: the AWS provider does not support both forms on one network ACL.

5. **Turn it on.** Ask ColorTokens to turn on Malicious Deny on AWS. Xshield then blocks the addresses of the **Malicious Deny** template, the malicious IP block template of this guide, for each workload it is assigned to, from the next time that workload's policy is deployed or regenerated. While the **Block Malicious IP Trigger** of the **Malicious IP Communication** alert rule is on, Xshield assigns the template to a workload that talks to a malicious address, and adds the address to it.

6. **Read the first plan.** It adds one entry for each address, direction and network ACL, and updates the receipt:

   ```
     # module.xshield_enforcement.aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"] will be created
     + resource "aws_network_acl_rule" "this" {
         + cidr_block     = "203.0.113.7/32"
         + egress         = false
         + id             = (known after apply)
         + network_acl_id = "acl-0a1b"
         + protocol       = "-1"
         + rule_action    = "deny"
         + rule_number    = 50
       }

     # module.xshield_enforcement.aws_network_acl_rule.this["acl-0a1b/out/203.0.113.7/32"] will be created
     # module.xshield_enforcement.xshield_aws_enforcement_receipt.this[0] will be updated in-place
   ```

   Under `Changes to Outputs`, `xshield_review` says the same in words, and how far each network ACL reaches beyond the template's workloads once the cloud connector has observed it:

   ```
   + "Network ACL acl-0a1b denies all inbound traffic from 203.0.113.7/32, which the malicious IP block template blocks.",
   + "Network ACL acl-0a1b denies all outbound traffic to 203.0.113.7/32, which the malicious IP block template blocks.",
   + "Network ACL acl-0a1b: AWS applies this network ACL to every resource in the subnets associated with it, so it blocks these addresses of the malicious IP block template for more than the workloads the template is assigned to: workloads the template is not assigned to, web-1. Any other resource in those subnets, such as a NAT gateway or a load balancer, can neither reach them nor be reached from them: 203.0.113.7/32.",
   ```

   An address that is missing from the plan is named in a notice of `xshield_aws_enforcement_status`: `networkAclEntryRefused` for no room or no rule number, `networkAclNotObserved` for a network ACL the cloud connector has not read, `networkAclEntryShadowed` for an allow of yours that lets its traffic through. The plan stops before anything is applied when the role cannot read network ACLs, or a network ACL it names no longer exists: see [When something goes wrong](#when-something-goes-wrong).

7. **Apply, then check.** After the apply, AWS shows each deny in front of your allows:

   ```sh
   aws ec2 describe-network-acls --network-acl-ids acl-0a1b \
     --query 'NetworkAcls[0].Entries[?RuleAction==`deny`].[Egress,RuleNumber,CidrBlock||Ipv6CidrBlock]' --output text
   ```

   Once the cloud connector has observed the account, `xshield_aws_enforcement_status` reads `state = "converged"` with no drift, and the monitor reports no `network_acl_block_not_enforced`. Xshield asks the cloud connector to observe the account every 10 minutes.

To stop blocking an address, remove it from the **Malicious Deny** template, or unassign the template from the workloads, in Xshield: the next enforcement run deletes its entries. Do not delete an entry in AWS or take it out of the state: an entry deleted outside Terraform is drift, which the next apply restores.

### 2. Databases, functions and services: the workspace that owns them attaches the group

The enforcement workspace attaches each instance's group itself. Terraform has no separate attachment for an RDS instance, Aurora cluster, Lambda function, Managed Flink application or App Runner service, so the workspace that owns one adds the group to the resource's own list.

That workspace declares nothing of Xshield's. The enforcement workspace creates the group and every rule in it, such as the `rds/orders-db/in/tcp/5432/10.20.1.11/32` rule in the plan above, and writes the group's ID to the SSM parameter `/colortokens/v1/rds/orders-db/security-groups`. The lookup module reads that parameter by the resource's handle:

```hcl
module "orders_db_xshield" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws-group-lookup?ref=v0.2.0"

  handle                 = "rds/orders-db"
  vpc_id                 = aws_security_group.orders_db.vpc_id
  own_security_group_ids = [aws_security_group.orders_db.id]
}

resource "aws_db_instance" "orders" {
  identifier = "orders-db"
  # ...
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}

output "xshield_security_group_ids" {
  value = module.orders_db_xshield.security_group_ids
}
```

- `module.orders_db_xshield.security_group_ids` is the group Xshield gave the database. Its rules show in the enforcement workspace's plan, never in this one.
- `aws_security_group.orders_db` is the database's own group, with the rules this workspace declares for it. Xshield's group goes beside it. Xshield changes a group of your own only under Full control, through step 4.
- `vpc_id` is the database's VPC. The lookup returns only Xshield's groups in it, as AWS refuses a group from another VPC. A resource moved to another VPC gets its group there once Xshield has discovered the move and the enforcement run has applied; until then the lookup returns nothing and warns.
- `own_security_group_ids` makes the plan fail, rather than the apply, when the database's own groups and Xshield's are more than AWS allows on it.
- The output shows Xshield's group in this workspace's plan, under `Changes to Outputs`, when it arrives and when it leaves.

`database/` is this workspace in full. Its `xshield.tf` holds everything the team adds, and its `main.tf` is the team's own code with the one changed line marked. `function/` is the same for a Lambda function.

| Resource | Handle |
|--|--|
| RDS instance | `rds/<DB instance identifier>` |
| Aurora cluster | `rds-cluster/<cluster identifier>` |
| Lambda function | `lambda/<function name>` |
| Managed Flink application | `flink/<application name>` |
| App Runner service | `apprunner/<service name>` |
| Auto Scaling group | `asg/<Auto Scaling group name>` |

An App Runner service takes groups only through its VPC connector, and every service on a connector gets the connector's groups, so give each service a connector of its own: see `apprunner/`.

An Auto Scaling group takes its group through its launch template, so new instances start with it. The enforcement run attaches the group to the instances that do not carry it yet. That holds while its instances have the same policy. Where they do not, Xshield reports `asgPolicyDiffers` and gives each instance a group of its own: the launch template then carries only the rules they all share, or nothing when they share none, and a new instance gets its own group only once discovery finds it.

The lookup needs no Xshield credentials, only `ssm:GetParametersByPath` on `/colortokens/v1/*`. A resource Xshield lists no entry for gets an empty list, so its plan never depends on Xshield and attaches nothing from it, and the output above is empty. The lookup reads the entry only when its own workspace plans, so a new resource's workspace must run again after Xshield has discovered the resource and the enforcement run has written its entry: until then the resource carries no Xshield group, and Xshield reports it as `memberUnattached`. A misspelt handle therefore attaches nothing, and Xshield reports the resource as `memberUnattached`. To have the plan warn whenever a handle has no entry, set `warn_when_unlisted = true`; the warning is then expected on the run that creates the resource, and for a resource Xshield's policy gives nothing to attach.

In an account the cloud connector enforced, add the lookup only once the first enforcement apply, the one with `handover/`, has succeeded: until that apply has written the resource's entry, the lookup returns no group, and an apply takes the connector's group off the resource. Where an earlier move to connector delivery put the resource's group attribute in `ignore_changes`, as [Stop enforcing](#stop-enforcing) says, take it out in the same change, or point a module call back from the copy of its module that ignores it: while it is ignored, the lookup attaches nothing and takes nothing off.

### 3. Instances whose Terraform declares their security groups

Nothing to do for instances no workspace manages one by one, such as Auto Scaling instances. If a workspace sets `vpc_security_group_ids` on an `aws_instance`, or `security_groups` on an `aws_network_interface`, that list is authoritative and removes the group the enforcement workspace attached. Tell Terraform to leave it alone, before the enforcement workspace's first apply, so no apply of that workspace runs while its instances carry the group:

```hcl
resource "aws_instance" "web" {
  # ...
  lifecycle {
    ignore_changes = [vpc_security_group_ids]
  }
}

resource "aws_network_interface" "web" {
  # ...
  lifecycle {
    ignore_changes = [security_groups]
  }
}
```

While the list is ignored, Terraform no longer applies your own edits to it: add or remove your own groups on such an instance with `aws_network_interface_sg_attachment`, which leaves Xshield's group in place. An instance whose group another workspace took off shows in `xshield_aws_enforcement_status` as a `memberUnattached` finding, with `restoration = "pipeline"`, at the cloud connector's first observation after that apply; the next enforcement apply attaches the group again.

### 4. Full control: declare your own groups' rules through the rules module

Skip this step unless you use Full control. Under Full control Xshield also narrows a broad rule in a security group of your own, such as `0.0.0.0/0` on port 443. In pipeline delivery this goes through your code. The enforcement workspace changes only Xshield's own groups, so a rule leaves a group of yours in a plan of the workspace that owns the group. That workspace declares the group's rules through `modules/aws-security-group-rules`, and the module leaves a rule out once Xshield says it is safe to.

A person does this step once for each group. From then on Xshield decides which of the declared rules are created, and an approved change needs no edit to the workspace.

In the workspace that owns the group:

1. Configure the `xshield` provider as in step 1. The API key's user must be able to read cloud snapshots and to create enforcement receipts. The built-in ADMIN and USER roles allow both.
2. Read `xshield_aws_security_group_changes` once, in the root module. It lists the groups in the account and region that an approved change applies to.
3. Declare each group's rules through one module block, and pass that data source to every block.

```hcl
provider "xshield" {} # credentials from XSHIELD_* environment variables

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id
}

module "web_rules" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws-security-group-rules?ref=v0.2.0"

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = aws_vpc.main.id
  group_name        = aws_security_group.web.name
  security_group_id = aws_security_group.web.id

  ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
  egress_rules = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
  }
}
```

`ingress_rules` and `egress_rules` are maps. Each key is a name you choose and keep. Each value takes the arguments of `aws_vpc_security_group_ingress_rule` or `aws_vpc_security_group_egress_rule`, and the module creates one such resource per rule. Do not also declare the group's rules inline, in `ingress` or `egress` blocks of the `aws_security_group`: the AWS provider's documentation warns that mixing the two causes conflicts and overwritten rules.

A rule the workspace already manages as a rule resource becomes a map entry with the same arguments, and a `moved` block tells Terraform it is the same rule:

```hcl
# Before
resource "aws_vpc_security_group_ingress_rule" "https_all" {
  security_group_id = aws_security_group.web.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# After: the https_all entry of the map replaces that block, with
moved {
  from = aws_vpc_security_group_ingress_rule.https_all
  to   = module.web_rules.aws_vpc_security_group_ingress_rule.this["https_all"]
}
```

The plan then shows the rule as `has moved to`, and nothing in AWS is added or destroyed. The one resource it adds is `terraform_data.xshield_routed`, the [record the module keeps in state](../../modules/aws-security-group-rules/README.md#the-record-kept-in-state).

`full-control/` is this workspace in full. Its `xshield.tf` holds everything the team adds, and its `main.tf` is the team's own code with the two changes marked.

#### A group whose rules are declared another way, or not in Terraform

A group you already have keeps every rule through this step: the rules are in AWS already, so the change carries each one into the module instead of creating it. How depends on how the group's rules are declared today.

| The group's rules today | The one-time change |
|---|---|
| `aws_vpc_security_group_ingress_rule` and `aws_vpc_security_group_egress_rule` resources | A map entry and a `moved` block for each rule, as above. |
| Inline `ingress` and `egress` blocks of the `aws_security_group` | Delete every inline block of the group. Add a map entry and an `import` block for each rule. |
| `aws_security_group_rule` resources | Add a map entry and an `import` block for each rule, and a `removed` block for each old resource. |
| No Terraform: the group was made in the console, by a script or by another tool | Add an `aws_security_group` block with the group's own name and description, an `import` block for the group, and a map entry and an `import` block for each rule. |

An `import` block names a rule by its security group rule ID. To list a group's rules with their IDs:

```bash
aws ec2 describe-security-group-rules --filters Name=group-id,Values=<group ID>
```

A group with inline rules:

```hcl
# Before
resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# After: the group keeps its block without the ingress block, the https_all
# entry of the map declares the rule, and
import {
  to = module.web_rules.aws_vpc_security_group_ingress_rule.this["https_all"]
  id = "sgr-0a1b2c3d4e5f60101"
}
```

A group whose rules are `aws_security_group_rule` resources. Terraform cannot move that type into the one the module uses, so a `moved` block fails the plan. The `removed` block makes Terraform forget the old resource and leave its rule in AWS, and the `import` block brings the rule in under its key:

```hcl
# Before
resource "aws_security_group_rule" "app_from_web" {
  type                     = "ingress"
  security_group_id        = aws_security_group.app.id
  protocol                 = "tcp"
  from_port                = 8080
  to_port                  = 8080
  source_security_group_id = aws_security_group.web.id
}

# After: the from_web entry of the map replaces that block, with
removed {
  from = aws_security_group_rule.app_from_web

  lifecycle {
    destroy = false
  }
}

import {
  to = module.app_rules.aws_vpc_security_group_ingress_rule.this["from_web"]
  id = "sgr-0a1b2c3d4e5f60201"
}
```

`full-control-adopt/` is a workspace with one group of each of the last three kinds. Its `adopt.tf` holds the `import` and `removed` blocks. Delete them once the plan that uses them is applied.

Read the first plan before you apply it. For each group it imports the rules, and the group too when no Terraform managed it, and adds only `terraform_data.xshield_routed`. It destroys and replaces nothing. A plan that shows anything else has one of these causes:

- **A rule to destroy, inline rules.** Only some of the group's inline blocks of one direction were deleted. Terraform keeps the rules of a group with no inline block of that direction, and revokes the rules of the blocks deleted from a group that still has one.
- **A rule to destroy, `aws_security_group_rule`.** A resource block was deleted with no `removed` block for it.
- **A rule to create.** The rule has no `import` block, and the apply fails because the rule is already in the group. One `aws_security_group_rule` with several entries in `cidr_blocks` is one rule in AWS for each entry, so it becomes that many map entries and `import` blocks.
- **A group to replace.** The `name` or `description` of the new `aws_security_group` block differs from the group's own. A description cannot be changed in place, so Terraform plans a new group.
- **`Configuration for import target does not exist`.** The key of an `import` block is not a key of the map. Or a change that narrows the group was approved before this step, and Xshield already takes that rule out, so the module no longer declares it.

Do this step before a change that narrows the group is approved. If one was approved first, nothing is lost: the change waits, every workload keeps the access the rule gives, `xshield_aws_enforcement_status` reads `waiting`, and its `changeSetHeld` notice names the group and the rule. Once the module takes that rule out, its `import` block has no target. Delete that one `import` block and revoke that one rule yourself. That is the removal this workspace's plan would have made, and Xshield takes a rule out of the module only when every workload that still needs it carries its `ct-cohort-` group:

```bash
aws ec2 revoke-security-group-ingress --group-id <group ID> --security-group-rule-ids <rule ID>
```

For an egress rule the command is `revoke-security-group-egress`.

A group that stays outside Terraform is never changed by Xshield or by the enforcement workspace. A change that narrows one of its rules waits in the same way, until whoever owns the group takes the rule out and Xshield sees the group without it. A revert of that change waits for the rule to be put back the same way.

What a plan of this workspace shows:

- A group no approved change applies to plans exactly as its code declares it. The module reads nothing from Xshield for that group.
- When an approved change applies to the group, the module asks Xshield which declared rules to keep. A group is matched by its name and its VPC, so a group of the same name in another VPC is not affected. A rule is matched by what it allows: its direction, protocol, ports and source or destination. Its key plays no part in the match.
- A rule Xshield narrows stays in the plan until every workload that still needs it carries a `ct-cohort-` group that keeps that access. The enforcement workspace creates those groups, so run it first. The next plan of this workspace then removes the rule, and no workload loses access part-way.
- Until this workspace has applied, the group keeps its broad rule. `xshield_aws_enforcement_status` reads `waiting` while the change waits for this workspace, and the monitor reports `owner_apply_overdue` when the wait passes `max_owner_apply_age`.
- While an approved change applies to the group, the plan also shows two `xshield_aws_security_group_changes_receipt` resources, `applying` and `applied`. They tell Xshield which change sets the rules came from. The apply sends `applying` before any rule of the group is created or updated, and `applied` once they are. A rule the apply takes out of the group is destroyed after `applied`: see [How a revert waits for this workspace](#how-a-revert-waits-for-this-workspace).

Keep every rule in the map, before and after Xshield leaves it out. If you delete a rule yourself before Xshield leaves it out, the workloads that still rely on it lose that traffic early. If the change is reverted, the rule comes back only while your code still declares it. Do not add a rule that gives back traffic a change took away: every workload in the group gets that traffic again.

Before you approve a change in Xshield, read what its review lists for each group. A group of yours can also be attached to something Xshield does not enforce on, such as a load balancer, a VPC endpoint or an interface another AWS service manages. A rule Xshield narrows leaves the group for everything that carries it, and only the workloads Xshield enforces on get a `ct-cohort-` group that keeps the access. The review names each such resource in a `MEMBERS_LOSE_MOVED_RULE` warning, and Xshield approves the change only once you acknowledge each one. Give that resource a group of its own before you approve, or it loses the rule when this workspace applies.

A resource attached to the group after the approval was never shown to the person who approved it. Xshield names each such resource to this workspace's plan, and the module warns through its `unacknowledged_carriers` check:

```text
Security group web is also carried by lb-public, which Xshield does not enforce on and nobody acknowledged when the change was approved. They will lose the rules this apply takes out of the group. Deploy the change again in Xshield to review and acknowledge them, or give each its own security group first.
```

The warning does not stop the plan or the apply. Before you apply, deploy the change again in Xshield, so its review shows the resource and you can acknowledge it, or give the resource a security group of its own. The next plan then has no warning. The module's `unacknowledged_carriers` output lists the same names. To have the plan stop instead of warn, set `fail_on_unacknowledged_carriers = true` in the module call.

A plan of this workspace fails when Xshield cannot be reached. A plan that stops with `Invalid count argument` or `Invalid for_each argument` in the module is explained under [When something goes wrong](#when-something-goes-wrong). Policies that check the plans of workspaces that own such groups are provided by ColorTokens separately: see [`policies/`](policies/README.md).

#### How a revert waits for this workspace

While an approved change applies to a group, the module also declares two `xshield_aws_security_group_changes_receipt` resources. Both tell Xshield which change sets the group's rules came from, and the state each was in when the plan read it: `attaching`, `narrowing` or `restoring`.

- The apply sends the `applying` receipt first, before any rule of the group is created or updated: the rules wait for it.
- The apply sends the `applied` receipt once the group's rules are created or updated.
- A rule the apply takes out of the group is destroyed only after the `applied` receipt, as the module's rules set `create_before_destroy`.

Terraform orders the removal of a rule that is no longer declared by what the state recorded at the last apply. So the first apply after upgrading to a module version with `create_before_destroy` still destroys such a rule before it sends the `applying` receipt, as a module version without it did. Apply each workspace once after the upgrade, before a change narrows its group, if you can. An apply with no changes is enough.

The two share one ID, kept for the module's life, and each apply that changes what they report sends both again under that ID. The module reports a change set as `narrowing` only when the group's code declares a rule the set takes out. Otherwise it reports the set as `attaching`, and a revert of it does not wait for this workspace.

When a change that narrowed the group is reverted, every workload keeps the access its `ct-cohort-` group gave until both of these are true:

- each receipt ID that reported the change narrowing the group has sent an `applied` receipt, after the revert, without it narrowing the group;
- Xshield then sees the group holding the rule again.

So after a revert, plan and apply each workspace that owns such a group. Until then `xshield_aws_enforcement_status` reads `waiting`. A `changeSetHeld` notice names each workspace by its receipt's label and ID.

A receipt sends what its plan read, so a plan saved before a revert still reports the change narrowing the group. Once the revert has been requested, Xshield refuses that plan's `applying` receipt, and the apply stops before any rule changes:

```text
Xshield no longer publishes change set <change set ID> as narrowing <group ID>: it was reverted or withdrawn after this plan was made. No rule waiting on this receipt was changed. Run a new plan and apply it now: it puts back any moved rule this apply took out of <group ID>.
```

Run a new plan in that workspace and apply it. With the module, no rule of the group changed. The error says only what holds however the rules are wired, as rules wired by hand without `create_before_destroy` are taken out before the receipt.

A revert can also be requested while such an apply runs, after Xshield took its `applying` receipt. The apply then takes the rule out of the group. The revert already waits for this workspace, so every workload Xshield enforces on keeps the access through its `ct-cohort-` group. The notice says the module applied a plan made before the revert. Run a new plan in that workspace and apply it: the rule comes back, and the `applied` receipt reports the revert.

If Xshield no longer publishes the change set at all when the `applied` receipt is sent, it refuses that receipt too, with the same error. The rules the apply created or updated are in place, and the rules it takes out are not yet out. Run a new plan and apply it.

A receipt's label defaults to the name of the HCP Terraform or Terraform Enterprise workspace. Elsewhere, set `receipt_label` in the module call, for example to the pipeline's name, so that the notice says which workspace to apply. If Xshield cannot take the `applying` receipt, the apply stops before any rule of the group changes: fix the cause and apply again. If Xshield cannot take the `applied` receipt, the apply fails after the group's rules are created or updated, and before any is taken out. Fix the cause and apply again: the apply sends the receipt, then takes those rules out. Until Xshield has it, a revert of a change it reports keeps the access.

Removing the module call, or destroying the workspace, destroys both receipts, and Xshield forgets their ID. Removing the call alone also destroys the group's rules: take a group out of the module as [the module's README](../../modules/aws-security-group-rules/README.md#taking-a-group-out-of-the-module) shows. Xshield keeps waiting for a receipt ID that no workspace declares any more, when a revert is of a change that ID reported narrowing a group. That happens when:

- the receipts are taken out of the workspace's state with `terraform state rm`, or by a `removed` block that does not destroy them;
- the workspace's state is rolled back to a version that holds another receipt ID, or none;
- the workspace is deleted without being destroyed.

The notice names the receipt's ID. A module's two receipts share that ID, so one import and one destroy make Xshield forget it:

1. In a new directory, configure the `xshield` provider and declare a receipt with any values:

   ```hcl
   resource "xshield_aws_security_group_changes_receipt" "orphan" {
     stage            = "applied"
     cloud_account_id = "123456789012"
     region           = "us-east-1"
     version          = "orphan"
     groups           = {}
   }
   ```

2. Import the receipt by the account, the region and the ID the notice names, then destroy it:

   ```bash
   terraform init
   terraform import xshield_aws_security_group_changes_receipt.orphan "123456789012/us-east-1/<receipt ID>"
   terraform destroy
   ```

A module version from before receipts sends none. A revert of a change no receipt reported narrowing the group waits only until Xshield sees the group holding the rule again. A plan saved before the revert is then not caught. Applied after the revert has ended, it takes the rule out again, and the workloads that relied on the rule lose that access: no `ct-cohort-` group keeps it any more. The notice for such a group suggests upgrading. Upgrade the module's `ref`, and the `colortokens/xshield` provider, to versions that have `xshield_aws_security_group_changes_receipt`. The first plan after the upgrade adds the two receipts for each group a change applies to, and changes nothing in AWS.

### 5. Monitor

Run `monitor/` as a workspace of its own, on a schedule. It reads the status of one account and region and reports each thing that is wrong as a named check, in words a reviewer without portal access can act on. Once the account is handed back to the cloud connector, it reports nothing: the status keeps what it showed at the hand-over, and no pipeline run can change it.

Xshield also raises a `Cloud Policy Drifted` alert in the portal for each drift finding it records, and turns that alert rule on for a tenant when one of its accounts moves to pipeline delivery.

| Problem | Reported when |
|---|---|
| `drift_high` | The cloud differs from what was applied and access may be wider than approved. |
| `drift_medium` | The cloud differs in a way the next enforcement apply restores. |
| `drift_unrestored` | Drift Xshield recorded more than `max_apply_age` (24h) ago is still there: no enforcement run has restored it, it must be removed by hand, or, for a finding whose `restoration` is `approval`, a change must be approved in Xshield, as the finding says. One line for each finding, with when it was detected. |
| `workload_not_enforced` | Xshield could not write a group for a workload. The message names it and the reason. |
| `awaiting_attach` | A workload whose own workspace attaches Xshield's group, such as a database, a function or an Auto Scaling group, has not been shown carrying it since the last apply, so its policy is not enforced. One line for each workload, which says which workspace to apply: see step 6. |
| `prefix_list_size_unknown` | A group's rules name a prefix list Xshield has not sized, or the cloud connector cannot read the region's prefix lists, so Xshield's count of the group's rules is a guess and AWS may refuse them as over the quota of rules per security group. One line for each cause, unsized lists or a failed read, which names the groups and, for a failed read, ends with the connector's reason. |
| `apply_overdue` | Newer approved policy has waited longer than `max_apply_age` (24h) for an enforcement run. The message counts and lists the groups to create, the rules to add and remove, and the attachments to add. It does not count network ACL entries: when nothing it counts is waiting, it says so, and the enforcement plan shows the entries. |
| `never_applied` | Published policy has never been applied, for longer than `max_apply_age`. |
| `owner_apply_overdue` | A Full control change has waited longer than `max_owner_apply_age` (24h) for the workspace that owns a customer security group. One line for each change set and group, which lists the workloads it holds. |
| `pipeline_stopped` | No enforcement plan has run for longer than `max_run_gap` (72h). Raise it if that pipeline runs only on a change. |
| `drift_not_evaluated` | Xshield has not looked for drift for longer than `max_unobserved_age` (30m): no observation followed the last apply, or the latest one is that old. Xshield asks the cloud connector to observe the account every 10 minutes. No finding then means nobody looked. |
| `port_not_narrowed` | A port is still deployed in Xshield after the Full control change that narrowed its customer security group was reverted. One line for each port, group and change set, which lists the workloads. |
| `carriers_not_acknowledged` | A Full control change moves rules out of a customer security group that something carries which no approval of the change showed, such as a load balancer. Xshield keeps those rules until the carriers are acknowledged by deploying the change again; if the group's own workspace already applied, they have lost the rules. One line for each group, which names the carriers. |
| `block_rule_not_enforced` | A workload has a block template in Xshield, which AWS does not enforce: a security group can only allow, so the traffic the template blocks passes wherever an allow rule covers it. Remove those ports from the templates and security groups that allow them for the workload. A line for the malicious IP block template says that no network ACL entry of Xshield's blocks its addresses for the workload: the cloud connector has shown no network ACL in front of it, so check that the connector observes the account and the workload's subnet, or the account does not block on network ACLs, so follow [Turning on the malicious IP block](#turning-on-the-malicious-ip-block). One line for each template and set of ports, which lists the workloads. A workload whose malicious IP block template Xshield blocks on its network ACL is not listed for that template: `network_acl_block_not_enforced` reports any of its addresses that are not blocked there. |
| `network_acl_block_not_enforced` | Addresses of the malicious IP block template are not blocked on a network ACL in front of a workload: the network ACL has no room left (`ACL_FULL`), no rule number is free in front of the allows that cover them, nor among the even numbers from 50 to 98 (`NO_FREE_SLOT`), the addresses wait for the places of entries the same version removes (`AWAITING_REMOVAL`), the cloud connector has not read the network ACL (`NOT_READ`, `NOT_FOUND`), or an allow numbered below Xshield's deny, with no rule number free in front of it, lets their traffic through. One line for each network ACL and cause. |
| `unpublished` | Xshield has published nothing here: the wrong tenant, or an account that is not onboarded. Not warned by default. |
| `group_withdrawing` | Policy no longer uses a group, but something still holds it: a workload whose own workspace has not detached it yet, or, for a Lambda function, a published version or a network interface AWS has not released. Xshield keeps the group, with its rules, and the enforcement workspace deletes it at its first apply after nothing holds it: see step 6. One line for each group, which says what holds it and what to do. |
| `asg_policy_differs` | The instances of an Auto Scaling group have different policies, so each has a group of its own. One line for each Auto Scaling group. Not warned by default. |
| `workload_contained` | Xshield contained a workload, so its group stays off its interfaces until the containment is reverted. One line lists the workloads. Not warned by default. |
| `asset_policy_in_test` | A workload's asset policy is in test. On AWS that writes no rule: a security group can only allow, so a test-wide allow of the intranet would open every port the workload's own groups keep closed. Those groups keep deciding the ports and destinations the policy does not allow. One line for each direction, which lists the workloads. Not warned by default. |
| `revert_ended` | A Full control revert ended without discovery showing the customer security group holding its moved rules again, because nothing carried the group. The line says whether the group's own workspace has put the rules back, or to plan and apply it before anything carries the group again. Not warned by default. |

Notices about one group that differ only in their workload share a line, so one change held for ten workloads prints one line:

```text
A Full control change in 123456789012/us-east-1 has waited more than 24h for the workspace that owns a customer security group:
  vpc-1/sg-web: the change waits for the enforcement workspace's next apply to write the rules this workload keeps into vpc-1/sg-web (change set cs-7a1, waiting since 2020-03-01T00:00:00Z; workloads: app-01, app-02, app-03, app-04, app-05, app-06, app-07, app-08, app-09, app-10)
```

Every check only warns, so the monitor never blocks a pipeline unless you ask it to. Choose what it warns about with `warn_on`. Name a problem in `fail_on` and the plan stops on it, with the same message, and no OPA or Sentinel:

```hcl
fail_on = ["drift_high", "never_applied"]
```

The monitor cannot show that a first apply worked. Until the cloud connector has observed the account after the apply, `drift_evaluated` is false and there is no finding to report, and `drift_not_evaluated` warns of that only once `max_unobserved_age` has passed. To check a first apply, read `xshield_aws_enforcement_status` once the observation has come: `drift_evaluated` is true, no `memberUnattached` finding or `awaitingAttach` notice names a workload, and each workload reads Synchronized in the portal. The guide's step 6 lists each check and what to do when it fails.

The `problems` output carries the same report by name, for a job that posts it somewhere. The workspace manages no resources, so `-detailed-exitcode` says nothing about it. To learn from an exit code whether approved policy is applied, plan the *enforcement* workspace on a schedule with `-detailed-exitcode`: 2 means it has something to apply, which is approved policy not yet applied or a resource it manages changed in the cloud.

Where policy sets decide what blocks a run, use the example policy in [`policies/`](policies/README.md) in place of `fail_on`. [Exit codes and what stops a pipeline](#exit-codes-and-what-stops-a-pipeline) compares the choices.

### 6. Run the owners' workspaces after the enforcement workspace

A workspace from step 2 or step 4 changes only when it runs, and it reads what the enforcement workspace's apply wrote. Run them after every enforcement apply, in this order:

1. The enforcement workspace.
2. Each workspace with the lookup module (step 2). The group must exist, and its directory entry be written, before the lookup returns it.
3. Under Full control, each workspace with the rules module (step 4). A change takes a rule out of your group only once the enforcement workspace has written the rules each workload keeps into Xshield's groups and each workload carries them; until discovery shows a workload whose own workspace attaches its group carrying it, the change waits and this plan shows nothing to take out.

Run the chain by hand first, and check each workload as the guide's step 6 does, before you put it on a schedule. Then run it on a schedule as a whole, not only the enforcement workspace, and not only after an enforcement apply: a new resource gets its directory entry once Xshield has discovered it, and a held change is released at a discovery. A run with nothing to change plans no change and applies nothing. A workload reads Synchronized, and its `awaitingAttach` notice clears, at the cloud connector's first observation after its owner's apply.

In HCP Terraform or Terraform Enterprise, give each owner's workspace a run trigger whose source is the enforcement workspace, so a run is queued in it after each successful apply there. The triggered run waits for someone to confirm its apply unless the workspace sets `auto_apply_run_trigger = true`:

```hcl
data "tfe_workspace" "xshield_enforcement" {
  name         = "xshield-enforcement-us-east-1"
  organization = "example-org"
}

data "tfe_workspace" "orders_db" {
  name         = "orders-db"
  organization = "example-org"
}

resource "tfe_run_trigger" "orders_db_after_xshield_enforcement" {
  workspace_id  = data.tfe_workspace.orders_db.id
  sourceable_id = data.tfe_workspace.xshield_enforcement.id
}
```

In your own CI, make each owner's job run after the enforcement job: `needs` in GitHub Actions and GitLab CI, `dependsOn` in Azure Pipelines. Let each job with the lookup module run when the enforcement job fails too (`if: ${{ !cancelled() }}` in GitHub Actions, `when: always` in GitLab CI, `condition: succeededOrFailed()` in Azure Pipelines). An enforcement apply removes a group's directory entry before it deletes the group, and AWS refuses to delete a group a resource still carries, as after pinning `snapshot_version` to a version without it, so only the owner's apply can free the group. Such a job reads only complete entries: the enforcement apply writes the directory entries only once every rule is in place, so after a failed apply a lookup returns what the last complete apply wrote, or no group where none has completed yet, which is why step 2 adds a lookup in an account the cloud connector enforced only after the first apply. Make each job with the rules module wait for the enforcement job to succeed. [`chain/xshield-enforcement.yml`](chain/xshield-enforcement.yml) runs all three steps as GitHub Actions jobs on one schedule.

#### When policy stops using a group

After a rollback, an undeploy or a workload leaving policy, the same order removes the group:

1. The enforcement workspace's apply empties the workload's directory entry. It keeps the group and its rules, so the workload loses no access while it still carries the group.
2. The owner's workspace takes the group out of the resource's own list at its next run. An Auto Scaling group's running instances keep it until they are replaced, as below.
3. Once the cloud connector shows nothing holding the group, Xshield publishes a version without it, and the enforcement workspace's next apply deletes the group and its directory entry. In a chain that runs on a schedule, that is the next run's enforcement job. Nobody deletes the group by hand.

An Auto Scaling group's running instances keep the group they launched with, and Xshield keeps the group, as `withdrawing`, until they have been replaced from a launch template version without it. The owner's apply writes such a version; the Auto Scaling group launches from the version it names, which is the template's default version unless it names another.

AWS keeps a Lambda function's network interface for some time after its configuration changes, and a published version of the function keeps the configuration it was published with, so delete the versions that list the group once no alias uses them. Until nothing holds the group, the `withdrawing` notice says what does, and the monitor warns of it as `group_withdrawing`. Under Full control, a revert first gives your group back the rules it moved, as below, and the group that kept them for the workload then leaves in the same way.

A revert under Full control goes the other way: [How a revert waits for this workspace](#how-a-revert-waits-for-this-workspace) asks for the owner's workspace first. The chain is still safe when the enforcement workspace runs first: every workload keeps its access until the owner's workspace has put the rule back, and the next enforcement run then takes out what the revert removes.

## Exit codes and what stops a pipeline

Terraform reports a problem as a warning or as an error, and only an error stops a run.

| Terraform reports | What it does to the run | Where these examples use it |
|--|--|--|
| A failed `check` block | A warning. The plan and the apply go ahead, and the exit code is the same as without it. | Every check in `monitor/`. `xshield_published` and `interfaces_have_room` in `modules/aws`. `directory_entry` in `modules/aws-group-lookup`. `unacknowledged_carriers` in `modules/aws-security-group-rules`. |
| A failed precondition or postcondition | An error. The plan stops with exit code 1, so nothing is applied. | In `modules/aws`: a snapshot for another account or region, groups in the account while nothing is published, and a pinned version that puts a cohort group on a full interface that also loses one of Xshield's groups. In `modules/aws-group-lookup`: a handle without a kind, and more groups than the resource can carry. In `modules/aws-security-group-rules`: a resource nobody acknowledged, with `fail_on_unacknowledged_carriers` set. In `monitor/`: a problem named in `fail_on`. |
| A failed variable validation, or an error from a provider | An error, as above. | A reserved tag key in `modules/aws`. An empty `network_acl_arns` in `enforcement-role/`. A name `monitor/` does not know in `warn_on` or `fail_on`. Xshield cannot be reached. |

`terraform plan -detailed-exitcode` tells a plan that has something to apply from one that has nothing:

| Exit code | Meaning |
|--|--|
| 0 | The plan succeeded and has nothing to apply. |
| 1 | The plan failed. |
| 2 | The plan succeeded and has something to apply. |

A failed check does not change these codes. A plan that only warns still returns 0 or 2.

### The enforcement workspace

Plan it on a schedule with `-detailed-exitcode`:

- 2 means it has something to apply: approved policy that is not applied yet, or a resource it manages that changed in the cloud. Run the apply.
- 0 means AWS holds what was last applied, as far as Terraform can see. A rule someone adds to an Xshield group shows as a change of that group's `aws_vpc_security_group_rules_exclusive`, so the plan returns 2. With `enable_exclusive_rules = false`, Terraform does not manage such a rule, so it never shows here. Only the monitor reports it, as `drift_high`.
- 1 means the plan stopped. [When something goes wrong](#when-something-goes-wrong) lists the messages.

A workspace that exports outputs, as `enforcement/` does, returns 2 on its first plan even while nothing is published, because the outputs are new. Apply once and it returns 0.

In an account and region with many workloads, give each run room:

- **Time.** A plan reads every group and rule the workspace manages back from AWS, at least one request each. AWS limits how many of these requests an account makes in a region, and every tool that reads security groups there shares that limit, Xshield's discovery included. The AWS provider waits and retries when AWS throttles it, so a plan of thousands of rules slows down rather than fails, and can take several minutes. The first apply takes longer, because AWS also limits how fast rules are added. Set the job's timeout to match, and space scheduled runs so that one finishes before the next starts. If a run still stops with `RequestLimitExceeded`, raise `max_retries` in the `aws` provider block.
- **Memory.** Give the runner about 2 GB for 2,000 workloads, and about 1 GB more for every further 2,000.

### The monitor workspace

The monitor manages no resources, so `-detailed-exitcode` says nothing about enforcement there, and every monitor check only warns. To stop a pipeline on a problem, choose one of these:

- **`fail_on`.** The monitor's `problems` output has a precondition that fails while a problem named in `fail_on` is present. The plan then stops with exit code 1 and prints the message the check prints. A name in `fail_on` stops the plan even when `warn_on` leaves it out.
- **The example policy.** [`policies/`](policies/README.md) holds one example policy, `xshield-checks`, for the workspace that runs the monitor, written for Sentinel and for OPA. It reads the check results Terraform records in the plan and reports every failed check whose name starts with `xshield_`. It ships advisory. Raise its enforcement level and any failed Xshield check stops the run. `warn_on` then chooses which problems can stop it, because a problem `warn_on` leaves out fails no check. Use it in place of `fail_on` where policy sets decide what blocks a run. Outside HCP Terraform and Terraform Enterprise, `opa eval --fail-defined` over the JSON plan exits non-zero when an Xshield check failed.
- **The `problems` output.** It carries the same report by name, for a job of your own that reads it and decides.

Policies for groups under Full control are provided by ColorTokens separately.

## Stop enforcing

`terraform destroy` on the enforcement workspace is not the way to stop enforcing. Neither is deleting the `module "xshield_enforcement"` block. Both delete Xshield's groups and network ACL entries and tell Xshield nothing:

- Xshield keeps the last receipt, so `xshield_aws_enforcement_status` reads as it did before. The missing groups show only as drift findings, once the cloud connector observes the account.
- Under Full control the `ct-cohort-` groups are deleted too. They keep the access a workload still needs after a broad rule left one of your own groups, so those workloads lose that access.
- AWS refuses to delete a group that a database, function or service still carries, so the destroy can fail part-way.

To stop enforcing, withdraw the policy in Xshield by undeploying it, for the workloads concerned or for the whole account. Keep the enforcement workspace and keep running it. Xshield publishes a version without the groups, and the workspace removes them:

- An instance's group is detached and deleted by the enforcement run.
- A database's, function's or service's group goes in two steps. First its directory entry stops listing the group, so the workspace that owns the resource detaches it on its next apply. Xshield lists the group as `withdrawing`, and keeps its rules, until it sees the group detached. A later version then drops the group, and the enforcement run deletes it.
- A network ACL entry is deleted by the enforcement run once the version no longer blocks its address there, such as when the malicious IP block template is unassigned from the workloads behind the network ACL.
- When no group is left the run still sends its receipt, so Xshield knows the removal was applied.

When the account moves to connector delivery, nothing is destroyed either. The cloud connector then sets the groups of each database, function and service itself and leaves only its own groups on it, so the team's own groups come off too. A workspace that still applies its group lookup would put the team's groups back and take off any group the connector has added since, and in a chain built as step 6 says, the lookup workspaces run even when the enforcement job stops. Move in this order:

1. Before you switch the account to connector delivery in Xshield, give each workload, in Xshield's policy, any access that only its team's own groups allow.
2. Shortly before the switch, in each workspace with a group lookup, add the attribute that lists the resource's groups to `ignore_changes`, as the table below names it, and apply. The plan shows no change. From then on that workspace leaves the resource's groups as they are, so a group Xshield gives the resource before the switch is not attached.
3. Switch the account to connector delivery in Xshield.
4. In the enforcement workspace, follow `leave/`: its `removed` block makes Terraform stop managing the groups, rules, attachments, network ACL entries and directory parameters, and leaves them in the account. The cloud connector keeps the groups. The network ACL entries stay in place, and Xshield no longer tracks them, so the monitor no longer reports on them; a cloud connector that blocks addresses on network ACLs itself may change or delete an entry at a rule number it uses. List the entries and the directory parameters from the state before you apply, and once an address is no longer to be blocked, check that the entry at its number still denies it before you delete the entry, as `leave/leave.tf` says. Remove the outputs that read the module in the same change, or the configuration no longer validates. Then stop running the workspace.
5. In each workspace with a group lookup, remove the lookup module and the outputs that read it, give the resource only its own groups where it took the lookup's, and apply: in `database/`, `function/` and `apprunner/`, delete `xshield.tf` and make the line marked `Changed for Xshield` list the team's group alone. The plan shows no change. These workspaces no longer need to run after the enforcement workspace.
6. Under Full control, in each workspace that declares a group's rules through the rules module, stop managing those rules: the cloud connector now changes the rules of your groups that a change applies to, and an apply of the module would put back a rule the connector took out, or take out one it put back. Stop that workspace's runs from the switch until this step is applied. Replace each module block with `removed` blocks that keep the group's rules, remove `xshield_aws_security_group_changes` and what reads it, and apply. The plan shows the rules as no longer managed, and destroys any receipts the module holds, so Xshield forgets them, and the record the module keeps in state; nothing changes in AWS.

   ```hcl
   removed {
     from = module.web_rules.aws_vpc_security_group_ingress_rule.this

     lifecycle {
       destroy = false
     }
   }

   removed {
     from = module.web_rules.aws_vpc_security_group_egress_rule.this

     lifecycle {
       destroy = false
     }
   }
   ```

7. Delete each directory parameter once no workspace uses a lookup with its handle.

Without `ignore_changes`, removing a lookup, or deleting its parameter while a lookup still reads it, takes the group off the resource. If the account is switched before step 2, as when the enforcement plan stops with `Xshield moved <account>/<region> to connector delivery`, first stop the runs of the workspaces with a group lookup (in `chain/`, disable the workflow), do step 2 in each before it runs again, do step 1, then go on from step 4.

| Resource | Add to `ignore_changes` |
|--|--|
| `aws_db_instance`, `aws_rds_cluster` | `vpc_security_group_ids` |
| `aws_lambda_function` | `vpc_config[0].security_group_ids` |
| `aws_kinesisanalyticsv2_application` | `application_configuration[0].vpc_configuration[0].security_group_ids` |
| `aws_apprunner_service` | `network_configuration[0].egress_configuration[0].vpc_connector_arn`: the connector moves the service to a VPC connector that carries only its groups |
| `aws_apprunner_vpc_connector` | `vpc_connector_name` and `security_groups`, as `apprunner/` names the connector after its groups |
| `aws_launch_template` of an Auto Scaling group | `vpc_security_group_ids`, or `network_interfaces[0].security_groups` |

A resource declared inside a module takes no `lifecycle` block from the module call. In step 2, point that module call at a copy of the module in which the resource lists the attribute in `ignore_changes`, and apply: the resource keeps its address, so the plan shows no change and replaces nothing. The module's other calls keep the original. The copy stays in step 5.

If `terraform destroy` was run by mistake, run the enforcement workspace again. It creates what the current version lists and sends a new receipt.

## Try it locally

The module tests mock both providers, so they need no tenant or AWS account. Build the provider from this repository and point Terraform at it. Run these from this directory:

```bash
(cd ../.. && go build -o examples/enforcement-snapshot/bin/ .) && sed "s|/absolute/path/to/examples/enforcement-snapshot|$PWD|" dev.tfrc > .dev.tfrc
```

```bash
export TF_CLI_CONFIG_FILE="$PWD/.dev.tfrc"
(cd ../../modules/aws && terraform init -backend=false && terraform test)
```

`../../modules/aws-group-lookup`, `../../modules/aws-security-group-rules`, `enforcement-role/`, `monitor/`, `database/`, `apprunner/`, `full-control/` and `full-control-adopt/` have tests too. Run them the same way from their own directories. The test of `full-control-adopt/` needs Terraform 1.11 or later. `recovery/` and `handover/` hold a file for the enforcement workspace, not a workspace, so their tests run in a copy of one: each test file says how. `../../modules/aws/apply-order/` checks the order in which an apply creates and removes groups, rules and attachments, in a copy of `modules/aws` that logs each: its test file says how.

## What happens if

Each row is a mistake or a failure: what it does in AWS, what Xshield shows, and how to put it right. `state`, notices and drift findings are what `xshield_aws_enforcement_status` returns. Names such as `drift_high` are the monitor's problems. The messages a plan prints are listed under [When something goes wrong](#when-something-goes-wrong).

| What happens | In AWS | What Xshield shows | To put it right |
|--|--|--|--|
| Policy is approved in Xshield and the enforcement workspace has not run | No change. AWS keeps the policy last applied. | `state` is `pending`, or `unapplied` when nothing was applied before, with what is waiting and since when. The monitor reports `apply_overdue` or `never_applied` after `max_apply_age`. | Run the enforcement workspace. |
| The enforcement pipeline stops running | No change. Nothing newly approved is applied. | `last_checked_at` stops moving, whatever `state` says. The monitor reports `pipeline_stopped` after `max_run_gap`. | Start the pipeline again. The monitor runs as a workspace of its own, so it still reports. |
| Under Full control, the workspace that owns a group has not applied | The group keeps its broad rule, so the change is not in force for that group. No workload loses access. | `state` is `waiting`, and a `changeSetHeld` notice says what the change waits for. The monitor reports `owner_apply_overdue` after `max_owner_apply_age`. | Apply the workspace that owns the group. If it does not declare the group through `modules/aws-security-group-rules` yet, do step 4 first. |
| Under Full control, a change is reverted and a workspace that owns a group it narrowed has not applied since | The group still lacks the rule the change took out, and every workload keeps the access through its `ct-cohort-` group. | `state` is `waiting`, and a `changeSetHeld` notice names the workspace by its receipt's label and ID. | Plan and apply that workspace. |
| Under Full control, a plan saved before a revert is applied after the revert was requested | No rule changes: Xshield refuses the apply's `applying` receipt before any rule of the group changes. | The apply fails with `-> 409` and `No rule waiting on this receipt was changed`. | Run a new plan in that workspace and apply it. |
| Under Full control, a revert is requested while a workspace applies a plan that narrows its group, after Xshield took the apply's `applying` receipt | The apply takes the rule out of the group. Every workload Xshield enforces on keeps the access through its `ct-cohort-` group, because the revert waits for that workspace. | `state` is `waiting`, and a `changeSetHeld` notice says the workspace applied a plan made before the revert. | Run a new plan in that workspace and apply it. |
| Under Full control, a workspace whose module version sends no receipts applies a plan saved before a revert, after the revert has ended | The apply takes the rule out of the group again, and the workloads that relied on it lose that access: no `ct-cohort-` group keeps it any more. | No receipt reports the apply. | Run a new plan in that workspace and apply it, which puts the rule back. Then upgrade the module, as [How a revert waits for this workspace](#how-a-revert-waits-for-this-workspace) says. |
| Under Full control, a workspace no longer declares the receipts it sent: they were taken out of its state, its state was rolled back, or it was deleted without being destroyed | The group's rules stay as that workspace last applied them. | A revert of a change the receipt ID reported narrowing a group waits, and the `changeSetHeld` notice names the receipt's ID. | Import the receipt and destroy it, as [How a revert waits for this workspace](#how-a-revert-waits-for-this-workspace) shows. |
| Under Full control, a change narrows a rule of a group that a load balancer, a VPC endpoint or another resource Xshield does not enforce on also carries | When the workspace that owns the group applies, that resource loses the rule with everything else in the group, and it has no `ct-cohort-` group to keep the access. | The change's review named the resource in a `MEMBERS_LOSE_MOVED_RULE` warning, and the change was approved only once it was acknowledged. A resource attached after the approval is named in a warning from the `unacknowledged_carriers` check in the owning workspace's plan. | Before that workspace applies, deploy the change again in Xshield and acknowledge the resource, or give it a group of its own. Once it has lost the rule, revert the change in Xshield and apply the workspace that owns the group, which puts the rule back. Give the resource a group of its own, then approve the change again. |
| A Full control change is reverted while a port it narrowed stays deployed | Your group again allows more than the port's policy. | A `portNotNarrowed` notice for each workload. The monitor reports `port_not_narrowed`. | Deploy the port again and approve its change, or undeploy the port. |
| A workspace sets an instance's or an interface's security groups without `ignore_changes` | That workspace's next apply takes Xshield's groups off the instance or interface. Under Full control this can cut access a `ct-cohort-` group kept for the workload. | A `memberUnattached` drift finding of high severity. The monitor reports `drift_high`. | Add `ignore_changes` as in step 3, then run the enforcement workspace to attach the groups again. |
| A lookup handle is misspelt | The resource gets no Xshield group. Nothing else changes. | Xshield reports the resource as `memberUnattached`. The monitor reports `drift_high`. | Correct the handle. Set `warn_when_unlisted = true` to have the plan warn when a handle has no entry. |
| Resources are written by hand in place of `modules/aws` | Whatever the code declares is created. | Xshield refuses the receipt unless the resources are exactly the snapshot's, so the version is not recorded as applied. | Use `modules/aws`. |
| The AWS provider points at another account or region than the snapshot is for | Nothing. The plan stops. | Nothing is applied or confirmed. | Point the AWS provider at the account and region the snapshot is for. |
| Xshield has published nothing for the account and region: the account is not yet set to pipeline delivery, has no deployed policy, or the `xshield` provider points at another tenant | Nothing is created and no receipt is sent. The run warns through the `xshield_published` check. If the account already holds groups Xshield rendered, the plan stops and does not remove them. | The tenant the provider reads shows `state` as `unpublished`. The monitor reports `unpublished` only when `warn_on` names it. A tenant that does hold policy for the account sees no run, so that policy keeps waiting. | Check in Xshield that the account is set to pipeline delivery and has a deployed policy. Check `XSHIELD_SERVER_URL` and the API key. |
| Xshield cannot be reached, or refuses the API key | Nothing. The enforcement plan fails, and so does the plan of every workspace that uses `modules/aws-security-group-rules`. A workspace that uses only `modules/aws-group-lookup` is not affected: the lookup reads only SSM. | Nothing changes. | Check `XSHIELD_SERVER_URL` and the key's role, then run again. |
| `terraform destroy` is run on the enforcement workspace, or its module block is deleted | Xshield's groups are taken off instances and deleted, with their rules and directory parameters. Its network ACL entries are deleted, so the malicious IP block template's addresses are no longer blocked. Under Full control, workloads lose the access their `ct-cohort-` groups kept. | Nothing at first: Xshield keeps the last receipt. Drift findings follow once the cloud connector observes the account. | Run the enforcement workspace again. To stop enforcing, see [Stop enforcing](#stop-enforcing). |
| The enforcement workspace's state is lost | Nothing changes. The groups stay in place. | Nothing changes. Xshield still holds the last receipt. | Before any other apply, follow `recovery/`: its import blocks rebuild the state from the last receipt. A plan made without them warns that Xshield already holds a receipt for the account and region. The plan shows every resource as an import, with an in-place change on each group and each directory parameter: it sets attributes an import cannot read and writes each parameter again with the value it holds. No group, rule, attachment or network ACL entry changes, and no receipt is sent, unless one was deleted outside Terraform since. A rule added to an Xshield group by hand shows as an in-place change of that group's `aws_vpc_security_group_rules_exclusive`, and the apply removes it. An instance in the last receipt that has since been terminated has no attachment left to import: the plan leaves it out and sends the receipt again without it. A network ACL in the last receipt that has since been deleted has no entries left to import either: the plan leaves them out, a check names them, and the receipt is sent again without them. Xshield accepts it once the cloud connector has observed the network ACL gone; until then the apply ends with that refusal once the state is rebuilt, so run it again after the cloud connector's next observation. One deleted outside Terraform since stops the plan with `Cannot import non-existent remote object`, which names its address: add the key in its brackets to `skipped_imports` in `recovery.tf`, under its kind, and the apply creates it again. A directory parameter needs no key there: the plan leaves out one deleted since, and the apply writes it again. An entry whose receipted number now holds another entry in AWS stops the plan, which names the entry: add its key under `network_acl_entries` in `skipped_imports`. The apply then rebuilds the rest of the state and fails on that entry with `NetworkAclEntryAlreadyExists`, as the pinned version keeps its number. Delete `recovery.tf` and the pin, and run the workspace again once the cloud connector has observed the network ACL: Xshield gives the deny another number, and the run writes it there. If that plan warns that Xshield already holds an apply receipt for this account and region, apply it: it sends the receipt again. |
| Xshield records an apply's receipt, and its answer does not reach the run | Nothing changes. The apply fails sending the receipt, and the state holds everything else the apply did. | The receipt is recorded, as for an apply that got its answer. | Run the workspace again. Its plan warns `Xshield already holds the receipt this plan sends`, which says the receipt is exactly what this plan sends, and the apply sends it again. |
| A second enforcement workspace is pointed at an account and region another already applies to | Nothing until it is applied. Its apply would then try to create groups whose names are taken, which AWS refuses within a VPC. | Nothing changes. Xshield holds the first workspace's receipt. | Its plan warns that Xshield already holds a receipt and names the workspace that sent it. Do not apply it: keep one enforcement workspace for each account and region. |
| An account the cloud connector enforced moves to pipeline delivery, and the first enforcement apply runs without `handover/` | Nothing. The plan creates every group again, and AWS refuses each group the connector already created, whose name is taken in its VPC, with `InvalidGroup.Duplicate`. The connector's groups stay in place and enforced. | No receipt is sent, so `state` stays `unapplied`. | Add `handover/handover.tf` to the workspace and plan: the plan imports the connector's groups, rules and attachments and creates only what is missing. Apply, then delete the file. |
| The account moves to connector delivery and the enforcement workspace still runs | Nothing from this workspace: its plan stops with `Xshield moved <account>/<region> to connector delivery`. A workspace with a group lookup that does not yet ignore the resource's groups puts back, at each apply, the groups the connector takes off. | `state` is `handedOver`. | Unless it was done before the switch, first stop the runs of the workspaces with a group lookup, add the resource's group attribute to `ignore_changes` in each, and give each workload in Xshield's policy any access only its team's own groups allowed, as [Stop enforcing](#stop-enforcing) says. Then replace the module block with `leave/leave.tf`, remove the outputs that read the module, apply once, stop running the workspace, and remove the lookups. |
| A rule is removed from an Xshield group outside Terraform | The traffic the rule allowed is blocked until the next enforcement apply puts the rule back. | A `ruleMissing` drift finding of medium severity. The monitor reports `drift_medium`, and `drift_unrestored` once the finding is older than `max_apply_age`. | Run the enforcement workspace. |
| A rule is added to an Xshield group outside Terraform | Access is wider than approved until the next enforcement apply removes the rule. Its plan shows the removal as an in-place change of the group's `aws_vpc_security_group_rules_exclusive`. With `enable_exclusive_rules = false`, the rule stays: no enforcement run removes it. | A `ruleUnmanaged` drift finding of high severity. Its `restoration` is `pipeline`, or `manual` with `enable_exclusive_rules = false`. The monitor reports `drift_high`. | Run the enforcement workspace. With `enable_exclusive_rules = false`, remove the rule by hand. |
| A network ACL entry Xshield applied is deleted or changed outside Terraform | Traffic from or to its address passes until the deny is in place again. The next enforcement apply creates a deleted entry again. An entry changed in place, or another entry written at the deleted entry's number, stops the next enforcement plan before anything is applied, with `AWS now holds another entry at rule number`: Terraform deletes an entry by its number, so holding that entry in state would delete it when the deny moves or is removed. A removal is not checked: if the version stops blocking the address first, the apply deletes whatever entry AWS holds at that number. If the cloud connector observes the change before an enforcement plan runs, Xshield gives the deny another number, and that plan writes the deny there and then deletes the entry at the old number, whatever it holds. | A `networkAclEntryMissing` or `networkAclEntryModified` drift finding of high severity, which the pipeline restores. The monitor reports `drift_high`, and `drift_unrestored` once the finding is older than `max_apply_age`. | Run the enforcement workspace. If the entry is deleted again each time another workspace applies, that workspace declares the network ACL's entries as a whole: change it as step 4 of [Turning on the malicious IP block](#turning-on-the-malicious-ip-block) says. Before you apply a plan that replaces or deletes an entry, check that the entry at its old number is still Xshield's deny, as [Malicious IP block on network ACLs](#malicious-ip-block-on-network-acls) shows, and run `terraform state rm` on any that is not. If the plan shows that entry as a deposed object, follow that section first: `terraform state rm` also takes any deny at its new number out of state. When its plan stops, run `terraform state rm` on the entry the error names, then plan again: Terraform no longer holds the entry at the old number, and once the cloud connector observes the network ACL, the deny is written at another number in front of every allow that covers the address. Until then, an apply fails with `NetworkAclEntryAlreadyExists` at the old number. |
| An allow entry on a network ACL is numbered below Xshield's deny of an address it covers | Traffic of that address passes, as AWS applies the lowest-numbered entry that matches, until the next enforcement apply after the cloud connector observes the allow. That apply writes the deny at a number in front of the allow, then deletes the old entry. No enforcement run changes your entry. When no number in front of the allow is free, the traffic keeps passing. | When the allow was added after the apply, a drift finding of high severity, which the pipeline restores. When no number in front of the allow is free, a `networkAclEntryShadowed` notice, and the finding must be resolved by hand. The monitor reports `drift_high` for the finding, and `network_acl_block_not_enforced` for the notice. | Run the enforcement workspace. For a `networkAclEntryShadowed` notice, free a rule number in front of the allow, number the allow higher, or narrow it so that it no longer covers the address. |
| A network ACL in front of a workload has no room for another entry, or no rule number is free in front of the allows that cover an address, nor among the even numbers from 50 to 98 | The address is not blocked there. Entries already applied stay, and the apply does not fail. | A `networkAclEntryRefused` notice with `ACL_FULL` or `NO_FREE_SLOT` and the direction, which names the addresses. The monitor reports `network_acl_block_not_enforced`. | Remove rules of your own from the network ACL, or raise the account's quota of rules per network ACL. For `NO_FREE_SLOT`, free a rule number in front of your allows that cover the address, or one of the even numbers from 50 to 98. Once the cloud connector observes the change, Xshield publishes a version that blocks the address. |
| The role the enforcement workspace assumes was created from a module version that did not block on network ACLs | Once Xshield blocks on a network ACL of the account, the enforcement plan stops at its read of the network ACLs with `UnauthorizedOperation` for `ec2:DescribeNetworkAcls`, before anything is applied. | No receipt is sent, so `state` stays `pending`. | Apply `enforcement-role/` from this module version, then run the enforcement workspace again. |
| A network ACL Xshield planned entries on is deleted | The enforcement plan stops before anything is applied, naming the network ACL, until the cloud connector observes it gone. Xshield then plans no entry for it, and the next plan goes ahead. | Once observed, a `networkAclNotObserved` notice with `NOT_FOUND`. The monitor reports `network_acl_block_not_enforced`. | Run the enforcement workspace again after the cloud connector's next observation. |
| A network ACL Xshield blocks on is also associated with subnets of other resources | Its entries block the template's addresses for every resource in those subnets too, such as workloads the template is not assigned to, a NAT gateway or a load balancer. | A `networkAclReach` notice, which the plan's `xshield_review` output repeats. The monitor reports nothing: nothing is refused. | Nothing, if those resources may lose those addresses. Otherwise put the template's workloads in subnets with a network ACL of their own. |
| The cloud connector has not read a network ACL in front of a workload | Nothing new is written to that network ACL. Entries already applied stay. | A `networkAclNotObserved` notice. The monitor reports `network_acl_block_not_enforced`. | Check that the cloud connector is running, is of a version that reads network ACLs, and can describe them. |
| AWS refuses a rule during an enforcement apply | The apply fails. The group keeps its old rules, because new rules are created before old ones are removed. | No receipt is sent, so the version is not recorded as applied. | Fix what AWS refused, then run the workspace again. |
| An apply stops before Terraform saves what it created: the runner is killed or loses its connection, or the run is force-canceled | AWS keeps what the apply created up to then, such as a group, a rule or a directory parameter, and the state does not hold it. The next apply tries to create it again, and AWS refuses with `InvalidGroup.Duplicate`, `InvalidPermission.Duplicate` or `ParameterAlreadyExists`. | No receipt is sent, so the version is not recorded as applied: `state` stays `pending`, or `unapplied` when nothing was applied before. | Import each resource the error names, as [An interrupted apply](#an-interrupted-apply) shows, then apply again. `recovery/` does not help here: it imports what the last receipt lists, and the interrupted apply sent none. |
| A workload has no room for another security group, or its group would pass the quota of rules per security group | Nothing new is written for that workload. One that carries an Xshield group keeps it, with the rules last applied. One that carries none gets none. | An `assetRefused` or `groupRefused` notice with the reason, such as `NO_FREE_SLOT`. The monitor reports `workload_not_enforced`. | Free a slot on the workload's interfaces, or raise the quota. For a group over the rule quota, see [`modules/aws/README.md`](../../modules/aws/README.md). |
| `snapshot_version` pins a version | The pinned version stays applied, at the rule numbers it gives its network ACL entries: an entry whose number now holds another entry in AWS stops the plan as usual, and after `terraform state rm` the apply fails on it with `NetworkAclEntryAlreadyExists` until the pin is removed. Entries of the version on a network ACL deleted since are left out, and a check names them. Until the cloud connector has observed that network ACL gone, the apply ends with the receipt refused. The directory parameters the version removes, and with exclusive rules the rules it drops from a group, go before the receipt is sent; the groups, rules, attachments and network ACL entries it deletes stay until a receipt is accepted. | Xshield reports the account as `pending` while the pin is in place. It refuses a receipt that leaves out entries of a network ACL until the cloud connector has observed the network ACL gone. | Plan and apply again once the cloud connector has observed the network ACL gone. Remove the pin when the rollback is over. |
| The cloud connector stops observing the account | Nothing. | `drift_observed_at` stops moving, and after the next apply `drift_evaluated` is false. No new drift finding is listed, which means nobody looked. The monitor reports `drift_not_evaluated` once the latest observation is older than `max_unobserved_age`. | Check that the cloud connector is running and can reach the account. |

### An interrupted apply

Terraform records what an apply creates in state as it goes. An apply stopped part-way, such as by a runner that is killed, can leave a resource that AWS created and the state does not hold. The next apply plans to create it again, and AWS refuses with `InvalidGroup.Duplicate` for a group, `InvalidPermission.Duplicate` for a rule, `NetworkAclEntryAlreadyExists` for a network ACL entry, or `ParameterAlreadyExists` for a directory parameter in SSM Parameter Store. The error names the resource on its `with` line, such as `with module.xshield_enforcement.aws_security_group.this["i-db-1"]`.

Bring each such resource into state under that address, then apply again:

1. If the state is still locked by the interrupted run, and no run is still applying, release it with `terraform force-unlock` and the lock ID the error gives.
2. Find each resource's ID in AWS. A group by the name and VPC the plan gives it: `aws ec2 describe-security-groups --filters Name=group-name,Values=<name> Name=vpc-id,Values=<vpc> --query 'SecurityGroups[].GroupId'`. A rule among its group's rules, by the protocol, ports and source or destination the plan gives it: `aws ec2 describe-security-group-rules --filters Name=group-id,Values=<group id>`. A directory parameter needs no lookup: its import ID is the `name` the plan gives it, which the error also names. Nor does a network ACL entry, whose import ID is `<network ACL ID>:<rule number>:-1:<egress>`, but import one only when the plan creates it, and first check that the entry at that number is the deny the plan gives it: `aws ec2 describe-network-acls --network-acl-ids <network ACL ID> --query 'NetworkAcls[].Entries'`. An entry that denies another address or protocol, or allows, is not the interrupted apply's: do not import it. When the plan replaces the entry instead, its `rule_number` changing, the apply stopped while moving the deny, and if the entry at the new number denies the plan's address on all protocols, it is the deny that now blocks the address: keep it. An import of it does nothing while the state holds the deny at its old number, so take that out of state first. Look at the entry at the old number: if it still denies the plan's address, delete it by hand, as the entry at the new number blocks everything it did: `aws ec2 delete-network-acl-entry --network-acl-id <network ACL ID> --rule-number <old number> --ingress`, or `--egress` for an outbound entry. Leave it if it holds anything else. Then run `terraform state rm` on the address the error names, and import the new number to it as step 3 shows: the plan shows the import and no change to the entry. See `NetworkAclEntryAlreadyExists` under [When something goes wrong](#when-something-goes-wrong).
3. Add an `import` block for each, to the address the error names, plan, and apply. Delete the blocks once applied.

```hcl
import {
  to = module.xshield_enforcement.aws_security_group.this["i-db-1"]
  id = "sg-0123456789abcdef0"
}

import {
  to = module.xshield_enforcement.aws_vpc_security_group_ingress_rule.this["i-db-1/in/tcp/5432/10.20.1.11/32"]
  id = "sgr-0123456789abcdef0"
}

import {
  to = module.xshield_enforcement.aws_ssm_parameter.directory["rds/orders-db"]
  id = "/colortokens/v1/rds/orders-db/security-groups"
}

import {
  to = module.xshield_enforcement.aws_network_acl_rule.this["acl-0a1b/in/203.0.113.7/32"]
  id = "acl-0a1b:50:-1:false"
}
```

The plan shows each as an import and creates the rest. Other resources take the import IDs `recovery/recovery.tf` uses: an attachment `<network interface ID>_<security group ID>`. Once a directory parameter is imported, the plan updates its value in place if it differs from the one the snapshot now gives. A rule left in a group of your own by an interrupted apply of the workspace that owns it is imported the same way, to `module.<name>.aws_vpc_security_group_ingress_rule.this["<key>"]` or its egress counterpart.

Deleting such a resource in AWS also clears the error, but only while nothing relies on it: AWS does not delete a group an interface carries, and a rule the interrupted apply created may be the one that now carries a workload's traffic.

A group the interrupted apply created can also be left behind by a version that no longer lists it, as when the change set a `ct-cohort-` group was for is reverted before the next run. That run neither creates the group nor knows of it, so nothing deletes it, and it counts against the account's security groups per VPC. In an account a pipeline delivers, after an apply of the enforcement workspace that succeeded, list the groups Xshield rendered for a pipeline in the region, and the groups the workspace's state holds:

```bash
aws ec2 describe-security-groups --filters Name=tag:ManagedBy,Values=ColorTokens Name=tag:ct:delivery,Values=pipeline --query 'SecurityGroups[].[GroupId,GroupName]' --output text
terraform show -json | jq -r '.values.root_module | .. | objects | select(.mode? == "managed" and .type? == "aws_security_group") | .values.id'
```

A group the first command lists and the second does not is no longer Xshield's. Delete it once no interface carries it: `aws ec2 describe-network-interfaces --filters Name=group-id,Values=<group ID> --query 'NetworkInterfaces[].NetworkInterfaceId'` lists none, then `aws ec2 delete-security-group --group-id <group ID>`. While the version still lists the group, import it instead, as above.

## When something goes wrong

| You see | It means | Do |
|--|--|--|
| `This snapshot is for A/R, but the AWS provider is configured for B/S` | The AWS provider points at another account or region than `cloud_account_id` or `region` | Point the AWS provider at the account the snapshot is for, or drop the inputs to use the provider's |
| `Cannot resolve the snapshot Xshield expects` | Xshield could not be reached as configured, or the API key's user cannot read cloud snapshots. An account with nothing published is not an error: the plan shows no change | Check `XSHIELD_SERVER_URL` and the key's role |
| Warning: `Xshield has published nothing for A/R, so this run creates nothing and sends no receipt` | The account is not yet set to pipeline delivery, has no deployed policy, or the provider reads another tenant or endpoint | If the account should have policy, check in Xshield that it is set to pipeline delivery and has a deployed policy, and check `XSHIELD_SERVER_URL` and the API key |
| `Xshield has published nothing for A/R, yet the account holds security groups Xshield rendered` | The provider reads another tenant or endpoint than the one that published the groups | Point the provider back at that tenant. Removing the module, as the message offers, deletes the groups and tells Xshield nothing, as `terraform destroy` does: to stop enforcing, see [Stop enforcing](#stop-enforcing) |
| `Xshield moved A/R to connector delivery` | The account's delivery is now the cloud connector, which keeps the groups this workspace created | Unless it was done before the switch, first stop the runs of the workspaces with a group lookup, add the resource's group attribute to `ignore_changes` in each, and give each workload in Xshield's policy any access only its team's own groups allowed, as [Stop enforcing](#stop-enforcing) says. Then replace the module block with `leave/leave.tf`, remove the outputs that read the module, apply once, stop running the workspace, and remove the lookups |
| `This provider version cannot apply this snapshot` | Xshield publishes a newer snapshot format | Upgrade the `colortokens/xshield` provider |
| `Xshield did not accept the apply receipt` | What was applied is not exactly what the snapshot lists | The details name the keys missing or unknown; use the enforcement module rather than hand-written resources. If they name `networkAclEntriesMissing`, a copy of the module older than network ACL blocking sends none: update it to this release's. While `snapshot_version` is pinned, the entries are on a network ACL deleted since: apply again once the cloud connector has observed it gone |
| `Xshield did not accept the apply receipt` with `-> 409` and `handed back to the cloud connector` | The account and region were handed back to the cloud connector after this run's plan was made. This workspace no longer delivers their policy, and Xshield refuses every receipt from it | Do not apply again. Unless it was done before the switch, first stop the runs of the workspaces with a group lookup, add the resource's group attribute to `ignore_changes` in each, and give each workload in Xshield's policy any access only its team's own groups allowed, as [Stop enforcing](#stop-enforcing) says. Then replace the module block with `leave/leave.tf`, remove the outputs that read the module, apply once, stop running the workspace, and remove the lookups |
| `-> 401: invalid signature` in any of these errors | Xshield did not accept the request's signature: the API key has expired or was deleted, `tenancy_id`, `user_id` or `fingerprint` is not that key's, `private_key` is not the private key of the key with that fingerprint, or the runner's clock is more than 10 seconds behind. Xshield's gateway can also refuse the signature of a receipt over about 8 KB; the message then gives the receipt's size | Check the key under **Settings > API Keys**, the credentials and the runner's clock, then run again. If they are right and the receipt is over 8 KB, running again may fail the same way: report it to ColorTokens support |
| `Cannot read the changes Xshield made to customer groups in A/R` | Xshield could not be reached as configured, or the API key's user cannot read cloud snapshots. An account and region with nothing published is not an error: every group keeps the rules its code declares | Check `XSHIELD_SERVER_URL` and the key's role |
| `Invalid count argument` or `Invalid for_each argument` in a `aws-security-group-rules` module | An approved Full control change applies to a group with this name, and the plan cannot know the group's VPC or one of its declared rules until apply: the same run creates the VPC or a group a rule references, or the module has a `depends_on` with pending changes. Or a change applies to some group in the account and region, and this group's own name is not known until apply, as `name_prefix` gives it on the run that creates the group. The plan stops rather than declare a rule Xshield has left out | Apply the new VPC or group first, for example with `-target`, then plan again; or drop the module's `depends_on`. While no change is published for the account and region, no group stops here |
| Warning: `Security group <name> is also carried by <resources>`, or the same as an error with `fail_on_unacknowledged_carriers` set | An approved Full control change takes rules out of the group, and each named resource carries the group, is not a workload Xshield enforces on, and was not acknowledged at approval, most often because it was attached since | Deploy the change again in Xshield and acknowledge each resource, or give each a security group of its own, then plan again |
| `Xshield did not accept the customer group changes receipt` with `No rule waiting on this receipt was changed. Apply again` | Xshield could not be reached, refused the API key or the `applying` receipt, or failed. With the module, the apply stopped before any rule of the group changed | Fix the cause, such as the key's role, then apply again |
| `Xshield did not accept the customer group changes receipt` with `The rules this receipt waits for are applied` | The group's rules are created or updated, none is taken out yet, and Xshield could not be reached, refused the API key or the `applied` receipt, or failed. Until Xshield has the receipt, a revert of a change it reports keeps the access | Fix the cause, such as the key's role, then apply again: the apply sends the receipt, then takes out the rules it removes |
| `Xshield did not accept the customer group changes receipt` with `-> 409` and `it puts back any moved rule this apply took out` | The plan was made before a change set it read as narrowing the group was reverted or withdrawn, and Xshield refused the receipt. With the module, no rule of the group was taken out | Run a new plan and apply it |
| `Xshield did not accept the customer group changes receipt` with `-> 404` and `no published snapshot` | The account and region have no published snapshot any more, so the changes this plan read no longer exist. Rules waiting on the refused receipt did not change | Run a new plan and apply it |
| `Xshield did not accept the customer group changes receipt` with `-> 409` and `handed over to the cloud connector` | The account and region moved to connector delivery, so Xshield refuses every receipt from this workspace. With the module, no rule of the group was taken out | Do not apply again: stop the workspace's runs and do step 6 of [Stop enforcing](#stop-enforcing) |
| `Xshield did not forget the customer group changes receipt` | Destroying the receipt failed: Xshield could not be reached, refused the API key, or failed. Until it forgets the receipt, a revert of a change it reported keeps waiting | Fix the cause, then destroy again |
| `handle must be <kind>/<name>` | The lookup's handle has no kind | Use one of the handles in the table above |
| Warning: `Xshield lists no entry for <handle>`, with `warn_when_unlisted` set | The resource is new and Xshield has not yet discovered it, Xshield's policy gives it nothing to attach, Xshield refuses it, or the handle is misspelt | Nothing for a new resource. Otherwise compare the handle with the enforcement module's `directory_entries` output, and look for the resource among the `assetRefused` and `groupRefused` notices of `xshield_aws_enforcement_status` |
| `InvalidGroup.Duplicate` or `InvalidPermission.Duplicate` when applying | An earlier apply stopped after AWS created the group or rule and before Terraform saved it in state | Import it, as [An interrupted apply](#an-interrupted-apply) shows, then apply again |
| `DependencyViolation`, or a timeout, deleting a security group in the enforcement apply | The version no longer has a group that a database, function, service or Auto Scaling group still carries, most often because `snapshot_version` is pinned to an earlier version. AWS refuses to delete a group in use. The apply has already removed the group's directory entry | Run the workspace that owns the resource, which takes the group off it, then run the enforcement workspace again. For an Auto Scaling group, that apply changes only its launch template: AWS refuses the delete until its running instances have been replaced from a version without the group, as [When policy stops using a group](#when-policy-stops-using-a-group) says. A chain built as step 6 says, such as `chain/`, runs the owners' jobs even when the enforcement job fails, so its next run does both |
| `InvalidGroup.Duplicate` on the first enforcement apply for an account the cloud connector enforced | The groups exist already: the connector created them, and the workspace did not take them over | Add `handover/handover.tf` to the workspace, plan and apply, then delete the file |
| `InvalidGroup.Duplicate` when applying a change that replaces one of your groups whose rules go through an `aws-security-group-rules` module | AWS cannot change a group's name, description or VPC in place, so Terraform replaces the group. The module's rules set `create_before_destroy`, which Terraform applies to the group they depend on too, so it creates the new group before destroying the old one, and AWS refuses a second group of the same name in a VPC. Importing does not help: the old group is already in state | Undo the change if the group can stay as it is. To replace the group, give it `name_prefix` instead of `name` in the same change |
| `NetworkAclEntryAlreadyExists` when applying, for `aws_network_acl_rule.this` | The network ACL already holds an entry at the rule number and direction the plan gives the deny. Either an earlier apply stopped after AWS created the deny and before Terraform saved it in state, or someone added an entry at that number after Xshield last observed the network ACL, or you removed an entry from state as a stopped plan asked | Look at the plan and at the entry in AWS. If the entry denies the plan's address on all protocols and the plan creates it, import it, as [An interrupted apply](#an-interrupted-apply) shows, then apply again. If it does and the plan replaces it, moving the deny to that number, keep that entry, which now blocks the address: take the old number out of state and import this one, as [An interrupted apply](#an-interrupted-apply) shows. Otherwise leave it: once the cloud connector observes the network ACL again, Xshield gives the deny another number, and the next plan and apply write it there |
| `NetworkAclEntryLimitExceeded` when applying, for `aws_network_acl_rule.this` | The network ACL has no room left in that direction in the account's quota of rules per network ACL: rules were added to it after the cloud connector last observed it, more than the two places Xshield leaves for yours. Entries already applied stay, and a deny that was moving keeps its old number, which no longer blocks its address, so the address passes until the deny can move | Plan and apply again after the cloud connector's next observation; Xshield asks for one every 10 minutes. Xshield then plans only what fits: it names an address it cannot add in a `networkAclEntryRefused` notice, and leaves a deny it cannot move at its old number. To block those addresses, and those of denies that could not move, remove rules of your own from the network ACL, or raise the quota |
| `UnauthorizedOperation` for `ec2:DescribeNetworkAcls` when planning, at `data.aws_network_acls.present` | Xshield blocks on a network ACL of the account, and the role cannot read network ACLs: it was created before network ACL blocking. Nothing was applied | Apply `enforcement-role/` from this module version, or add the action to your own role, then plan again |
| `Network ACL <ID> no longer exists in A/R` | The network ACL was deleted after Xshield planned entries on it. Nothing was applied | Plan again after the cloud connector's next observation; Xshield asks for one every 10 minutes. If the error stays, check that the cloud connector is running |
| `UnauthorizedOperation` when applying, for `aws_network_acl_rule.this` | The role's `network_acl_arns` leaves out the network ACL the entry goes in | Add the network ACL to `network_acl_arns` and apply `enforcement-role/`, or leave the input unset, then apply again |
| `Cannot import non-existent remote object` when planning with `recovery/recovery.tf` | An object of the last receipt was deleted outside Terraform since, so there is nothing at its ID to import | Add the key in the address's brackets to `skipped_imports` in `recovery.tf`, under its kind: `security_groups`, `rules`, `attachments` or `network_acl_entries`. Plan again: the plan creates it, and the apply writes it again. A directory parameter deleted since does not stop the plan: it is left out of the imports and written again |
| `ParameterAlreadyExists` when applying, for `aws_ssm_parameter.directory` | An earlier apply stopped after SSM Parameter Store created the directory parameter and before Terraform saved it in state | Import it by the parameter name the error gives, as [An interrupted apply](#an-interrupted-apply) shows, then apply again. Do not delete it instead: the lookup modules of other workspaces read it |
| `tags cannot set ManagedBy or a key starting with ct:` | A tag would hide the group from the cloud connector | Choose another tag key |
| The `monitor` check names a workload with `NO_FREE_SLOT` | Its interfaces already carry as many groups as AWS allows | Free a slot, or raise the account's security groups per interface quota |
| `These network interfaces carry as many security groups as the account allows` | An interface filled up since Xshield last discovered it, so its new group was left off this run | Free a slot on the named interface, or raise the quota; the next run attaches it |
| `<handle> would carry N security groups of its own and M of Xshield's` | The owning workspace's own groups and Xshield's are more than AWS allows on the resource | Drop one of its own groups, or raise the quota where AWS allows it |

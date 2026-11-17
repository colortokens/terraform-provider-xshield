---
page_title: "Enforce AWS policy through your own pipeline"
description: |-
  Step by step: apply the security groups Xshield renders for an AWS account through your own Terraform pipeline, and keep them applied.
---

# Enforce AWS policy through your own pipeline

Xshield renders every security group and rule for an AWS account and region, and the network ACL entries that block the malicious IP block template's addresses. Your pipeline applies them with the modules shipped in this provider's repository, and tells Xshield what it applied. You write no rule.

Each step below says who does it, what to run, and how to tell it worked. The [reference](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#readme) explains every choice and every message in more depth.

## Before you start

- An Xshield administrator has set the account to pipeline delivery.
- An Xshield API key for a pipeline user, created under **Settings > API Keys**. The user's role needs `READ_ENFORCEMENT_SNAPSHOT` and `CREATE_ENFORCEMENT_RECEIPT`, which the built-in ADMIN and USER roles have, and must cover every workload in the account.
- Terraform 1.7 or later, and the AWS provider 6.29.0 or later.

In every `source` below, replace `vX.Y.Z` with the tag of the `colortokens/xshield` provider release you run, so the modules and the provider match.

## Step 1: Give the runner the API key

Set these as secret environment variables on the runner of every workspace that configures the `xshield` provider. Nothing secret goes in the code.

| Variable | Value |
|--|--|
| `XSHIELD_SERVER_URL` | `https://<tenant>.colortokens.com` |
| `XSHIELD_TENANCY_ID`, `XSHIELD_USER_ID`, `XSHIELD_FINGERPRINT` | Shown with the API key under **Settings > API Keys** |
| `XSHIELD_PRIVATE_KEY` | The PEM private key itself, or set `XSHIELD_PRIVATE_KEY_PATH` to a file holding it |

## Step 2: Create the enforcement role, once per account

Whoever owns IAM in the account applies [`enforcement-role/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement-role), with `pipeline_principal_arns` set to the identities your runner uses. The role can change only security groups and rules tagged `ManagedBy = ColorTokens`, interface attachments, SSM parameters under `/colortokens/`, and entries of the account's network ACLs. To limit the network ACLs it may add entries to, list them in `network_acl_arns`.

**Done when** the apply prints `enforcement_role_arn`. Keep it for step 3.

## Step 3: Create the enforcement workspace, once per account and region

Start from [`enforcement/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement). In your copy, change the module's `source` from `../modules/aws` to the repository address, or `terraform init` fails:

```terraform
provider "aws" {
  region = var.region

  assume_role {
    role_arn = var.enforcement_role_arn
  }
}

provider "xshield" {}

module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws?ref=vX.Y.Z"
}
```

The module takes no policy input. It applies the snapshot for the account and region the AWS provider points at, and refuses one meant for any other.

If the cloud connector enforces this account and region today, add [`handover/handover.tf`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/handover) to the workspace before the first plan. The plan then imports the groups, rules and attachments the connector created, which stay in place and enforced, and creates only what is missing. Without it, the apply tries to create each group again and AWS refuses it with `InvalidGroup.Duplicate`. Delete the file after the first apply.

```shell
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Each change in the plan names the workload it is for. The apply creates Xshield's groups and rules, attaches each instance's group, writes a directory entry for each database, function and service, and sends the receipt last.

**Done when** a second `terraform plan -detailed-exitcode` returns `0`: AWS holds what Xshield published, and Xshield has the receipt.

## Step 4: Run it on a schedule

Plan the enforcement workspace on a schedule, and apply when the plan has changes:

```shell
terraform plan -detailed-exitcode -out=tfplan
# 0: nothing to apply. 2: approved policy or a change in AWS to apply. 1: the plan failed.
terraform apply tfplan
```

From here an approved policy change needs no edit to any code. It reaches AWS on the next run.

In an account and region with many workloads, give each run room:

- **Time.** A plan reads every group and rule the workspace manages back from AWS, at least one request each. AWS limits how many of these requests an account makes in a region, and every tool that reads security groups there shares that limit, Xshield's discovery included. The AWS provider waits and retries when AWS throttles it, so a plan of thousands of rules slows down rather than fails, and can take several minutes. The first apply takes longer, because AWS also limits how fast rules are added. Set the job's timeout to match, and space scheduled runs so that one finishes before the next starts. If a run still stops with `RequestLimitExceeded`, raise `max_retries` in the `aws` provider block.
- **Memory.** Give the runner about 2 GB for 2,000 workloads, and about 1 GB more for every further 2,000.

## Step 5: Attach groups to databases, functions and services

Skip this step if Xshield enforces only on EC2 instances. Terraform has no separate attachment for an RDS instance, an Aurora cluster, a Lambda function, a Managed Flink application or an App Runner service, so the workspace that owns one adds Xshield's group to the resource's own list. That workspace needs no Xshield credentials.

```terraform
module "orders_db_xshield" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-group-lookup?ref=vX.Y.Z"

  handle                 = "rds/orders-db"
  own_security_group_ids = [aws_security_group.orders_db.id]
}

resource "aws_db_instance" "orders" {
  # ...
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}
```

| Resource | Handle |
|--|--|
| RDS instance | `rds/<DB instance identifier>` |
| Aurora cluster | `rds-cluster/<cluster identifier>` |
| Lambda function | `lambda/<function name>` |
| Managed Flink application | `flink/<application name>` |
| App Runner service | `apprunner/<service name>` |
| Auto Scaling group | `asg/<Auto Scaling group name>` |

Apply that workspace after the enforcement workspace has applied. A new resource gets its group once Xshield has discovered it: apply its workspace again then.

**Done when** the resource lists Xshield's group beside its own. [`database/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/database) is a complete example.

## Step 6: Keep Xshield's groups on instances your code declares

Skip this step unless a workspace sets `vpc_security_group_ids` on an `aws_instance`, or `security_groups` on an `aws_network_interface`. Its next apply would take Xshield's group off. Tell Terraform to leave the list alone:

```terraform
resource "aws_instance" "web" {
  # ...
  lifecycle {
    ignore_changes = [vpc_security_group_ids]
  }
}
```

## Step 7: Full control only: declare your own groups' rules through the rules module

Skip this step unless you use Full control. Under Full control Xshield also narrows a broad rule in a security group of your own. The workspace that owns the group makes that change, through `modules/aws-security-group-rules`. Do this once for each group, before a change that narrows it is approved.

1. Configure the `xshield` provider as in step 1.
2. Read `xshield_aws_security_group_changes` once in the root module.
3. Move the group's rules into one module block. Give each rule a key you keep, and add a `moved` block for each rule resource you already have, so nothing in AWS changes.

```terraform
provider "xshield" {}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
}

module "web_rules" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-security-group-rules?ref=vX.Y.Z"

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = aws_vpc.main.id
  group_name        = aws_security_group.web.name
  security_group_id = aws_security_group.web.id

  ingress_rules = {
    https_all = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
  }
}

moved {
  from = aws_vpc_security_group_ingress_rule.https_all
  to   = module.web_rules.aws_vpc_security_group_ingress_rule.this["https_all"]
}
```

Rules declared inline, as `aws_security_group_rule` resources, or outside Terraform move with `import` and `removed` blocks instead: see the reference's [table of starting points](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#a-group-whose-rules-are-declared-another-way-or-not-in-terraform).

**Done when** the first plan shows each rule as moved or imported, adds only `terraform_data.xshield_routed`, and destroys nothing. Apply it.

Then, for each Full control change:

| When | Do |
|--|--|
| A change that narrows the group is approved | Run the enforcement workspace, then this workspace. The plan shows the rule taken out and two receipts, `applying` and `applied`. |
| The change is reverted | Plan and apply this workspace, then the enforcement workspace. Every workload keeps its access until this workspace has put the rule back. |
| An apply stops with `-> 409` and `Run a new plan and apply it now` | The plan was made before a revert. No rule changed. Run a new plan and apply it. |
| You upgrade the module from a version without receipts | Apply the workspace once, before a change narrows its group. An apply with no changes is enough. |

Keep every rule in the map, before and after Xshield leaves it out. If you delete one yourself first, the workloads that still rely on it lose that traffic early.

## Step 8: Watch it

Copy [`monitor/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/monitor) into a workspace of its own, set `cloud_account_id` and `region`, and plan it on a schedule. It manages no resources. Each problem, such as drift or an overdue apply, is a warning that says what to do. To stop a pipeline on a problem, name it in `fail_on`:

```terraform
fail_on = ["drift_high", "never_applied"]
```

**Done when** a plan of the monitor prints no warning.

## Later

| When | Do |
|--|--|
| You want to stop enforcing | Undeploy the policy in Xshield and keep running the enforcement workspace: it removes the groups. Do not run `terraform destroy` on it. |
| The account moves back to connector delivery | Replace the module block with [`leave/leave.tf`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/leave), remove the outputs that read the module, apply once, then stop running the workspace. |
| The enforcement workspace's state is lost | Before any other apply, add [`recovery/recovery.tf`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/recovery), read the plan, and apply. Its import blocks rebuild the state from the last receipt. |
| An apply stops part-way and the next one fails with `InvalidGroup.Duplicate`, `InvalidPermission.Duplicate`, `NetworkAclEntryAlreadyExists` or `ParameterAlreadyExists` | Import each resource the error names, then apply again: see [An interrupted apply](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#an-interrupted-apply). Import a network ACL entry only if it is the deny the plan gives. |
| Malicious Deny on AWS is to be turned on for an account already on this pipeline | First upgrade the module and the provider, apply `enforcement-role/` from the same release, and copy `monitor/` again; then ask ColorTokens to turn it on. In that order the pipeline keeps running, and nothing is written to a network ACL before the role can read and write it: see [Turning on the malicious IP block](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#turning-on-the-malicious-ip-block). |
| The monitor reports `network_acl_block_not_enforced` | Addresses of the malicious IP block template are not blocked on a network ACL: it has no room, the cloud connector has not read it, or an allow of yours is numbered below the deny. The warning says which and what to change: see [Malicious IP block on network ACLs](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#malicious-ip-block-on-network-acls). |
| A plan stops with any other message | Look it up under [When something goes wrong](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#when-something-goes-wrong). |

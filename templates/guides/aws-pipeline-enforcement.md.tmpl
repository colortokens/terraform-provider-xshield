---
page_title: "Enforce AWS policy through your own pipeline"
description: |-
  Step by step: apply the security groups Xshield renders for an AWS account through your own Terraform pipeline, and keep them applied.
---

# Enforce AWS policy through your own pipeline

Xshield renders every security group and rule for an AWS account and region. Your pipeline applies them with the modules shipped in this provider's repository, and tells Xshield what it applied. You write no rule.

Each step below says who does it, what to run, and how to tell it worked. Take them in order: each relies on the one before it. The [Xshield documentation](https://docs.xshield.colortokens.com/developer-tools/terraform/pipeline-delivery-aws) covers pipeline delivery in depth, including operations, recovery and troubleshooting.

## Before you start

- An Xshield administrator has set the account to pipeline delivery.
- An Xshield API key for a pipeline user, created under **Settings > API Keys**. The user's role must be able to read enforcement snapshots and create enforcement receipts, as the built-in ADMIN and USER roles can, and must cover every workload in the account.
- Terraform 1.7 or later, and the AWS provider 6.29.0 or later.
- A list of the workspaces that manage resources in the account and region. Three kinds change: one that declares an instance's or a network interface's security groups (step 3), one that owns a database, function, service or Auto Scaling group (step 5), and, under Full control only, one that owns a security group Xshield narrows (step 9). No other workspace changes.

Outside Full control, Xshield changes none of your own security groups: its groups sit beside each workload's own, and AWS allows what any of them allows.

The modules live in the [`modules/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/modules) directory of this provider's repository. Every `source` below is pinned to the provider release this page was published with. If you run another release of the `colortokens/xshield` provider, set `ref` to its tag, so the modules and the provider match.

## Step 1: Give the runner the API key

Set these as secret environment variables on the runner of every workspace that configures the `xshield` provider. Nothing secret goes in the code.

| Variable | Value |
|--|--|
| `XSHIELD_SERVER_URL` | `https://<tenant>.colortokens.com` |
| `XSHIELD_TENANCY_ID`, `XSHIELD_USER_ID`, `XSHIELD_FINGERPRINT` | Shown with the API key under **Settings > API Keys** |
| `XSHIELD_PRIVATE_KEY` | The PEM private key itself, or set `XSHIELD_PRIVATE_KEY_PATH` to a file holding it |

**Done when** the variables are set on each runner that step 4, step 6 and step 10 use, and under Full control step 9.

## Step 2: Create the enforcement role, once per account

Whoever owns IAM in the account applies [`enforcement-role/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement-role), with `pipeline_principal_arns` set to the identities your runner uses. The role can change only security groups and rules tagged `ManagedBy = ColorTokens`, interface attachments, SSM parameters under `/colortokens/`, and entries of the account's network ACLs. To limit the network ACLs it may add entries to, list them in `network_acl_arns`.

**Done when** the apply prints `enforcement_role_arn`. Keep it for step 4.

## Step 3: Keep Xshield's groups on instances your code declares

Skip this step unless a workspace sets `vpc_security_group_ids` on an `aws_instance`, or `security_groups` on an `aws_network_interface`. That list is authoritative: the workspace's next apply takes off the group the enforcement workspace attached. Tell Terraform to leave the list alone:

```terraform
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

Do this before the enforcement workspace's first apply in step 4. While the list is ignored, add or remove your own groups on such an instance with `aws_network_interface_sg_attachment`. Instances no workspace manages one by one, such as those of an Auto Scaling group, need nothing here.

**Done when** each such workspace has the `lifecycle` block on its default branch, and its plan shows no change to the list.

## Step 4: Create the enforcement workspace and apply it, once per account and region

Start from [`enforcement/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement). In your copy, change the module's `source` from `../../../modules/aws` to the repository address, or `terraform init` fails:

```terraform
provider "aws" {
  region = var.region

  assume_role {
    role_arn = var.enforcement_role_arn
  }
}

provider "xshield" {}

module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws?ref=v0.2.0"
}
```

The module takes no policy input. It applies the snapshot for the account and region the AWS provider points at, and refuses one meant for any other.

If the cloud connector enforces this account and region today, add [`handover/handover.tf`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/handover) to the workspace before the first plan, so the plan takes over the groups the connector created instead of creating them again. Delete the file after the first apply.

```shell
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Read the plan before you apply it. Each change names the workload it is for, by its instance ID or its handle, such as `rds/orders-db`.

**Done when** a second `terraform plan -detailed-exitcode` returns `0`. That does not yet show any workload carrying its group: step 6 does.

## Step 5: Attach groups to databases, functions and services

Skip this step if Xshield enforces only on EC2 instances. Terraform has no separate attachment for an RDS instance, an Aurora cluster, a Lambda function, a Managed Flink application or an App Runner service, so the workspace that owns one adds Xshield's group to the resource's own list. An Auto Scaling group takes its group the same way, through its launch template. That workspace needs no Xshield credentials.

```terraform
module "orders_db_xshield" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws-group-lookup?ref=v0.2.0"

  handle                 = "rds/orders-db"
  vpc_id                 = aws_security_group.orders_db.vpc_id
  own_security_group_ids = [aws_security_group.orders_db.id]
}

resource "aws_db_instance" "orders" {
  # ...
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}

output "xshield_security_group_ids" {
  value = module.orders_db_xshield.security_group_ids
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

Apply that workspace after the enforcement workspace has applied. A new resource gets its group once Xshield has discovered it: apply its workspace again then. In an account the cloud connector enforced, add the lookup only once the first enforcement apply, the one with `handover.tf`, has succeeded.

**Done when** the plan of each such workspace shows a group in `xshield_security_group_ids`, and after its apply the resource lists Xshield's group beside its own. [`database/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/database) is a complete example.

## Step 6: Check that each workload is enforced

The receipt says what your pipeline applied, not what each workload carries. That shows once the cloud connector next observes the account. Read it in a workspace of its own, configured as in step 1, which manages no resources:

```terraform
data "xshield_aws_enforcement_status" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

output "xshield_enforcement" {
  value = {
    state           = data.xshield_aws_enforcement_status.this.state
    drift_evaluated = data.xshield_aws_enforcement_status.this.drift_evaluated
    findings        = [for f in data.xshield_aws_enforcement_status.this.drift_findings : "${f.kind} ${coalesce(f.resource_name, f.resource, "-")}: ${f.detail}"]
    notices         = [for n in data.xshield_aws_enforcement_status.this.notices : "${n.code} ${coalesce(n.asset_name, n.group, "-")}: ${n.message}"]
  }
}
```

```shell
terraform apply -auto-approve
terraform output xshield_enforcement
```

Each finding and notice says what is wrong and what to do. A quiet [`monitor/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/monitor) right after an apply does not mean this check passed: it stays quiet until an observation is overdue.

**Done when** `state` is `converged`, `drift_evaluated` is `true`, `findings` is empty, `notices` holds only notices you have decided to accept, and every workload's **Policy status** in the Xshield portal reads **Synchronized**. If `drift_evaluated` stays `false`, check that the cloud connector is running and can reach the account.

## Step 7: Run the owners' workspaces after the enforcement workspace

Skip this step unless you did step 5, or will do step 9. Those workspaces change only when they run, and they read what the enforcement workspace's apply wrote. Run them after every enforcement apply, in this order:

1. The enforcement workspace.
2. Each workspace with the lookup module (step 5).
3. Under Full control, each workspace with the rules module (step 9).

In HCP Terraform or Terraform Enterprise, give each owner's workspace a run trigger whose source is the enforcement workspace. In your own CI, make each owner's job run after the enforcement job, and let jobs with the lookup module run even when the enforcement job fails. [`chain/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/chain) is a GitHub Actions example; leave out its `schedule` trigger until step 8.

**Done when** one run of the chain, started by hand, runs every workspace in this order, and a second run plans no change in any of them except what Xshield published after the first.

## Step 8: Run the chain on a schedule

Schedule the whole chain of step 7, not the enforcement workspace alone: some changes become ready when Xshield next discovers the account rather than at an apply. Without step 7, schedule the enforcement workspace alone. Each workspace plans, and applies when its plan has changes:

```shell
terraform plan -detailed-exitcode -out=tfplan
# 0: nothing to apply. 2: approved policy or a change in AWS to apply. 1: the plan failed.
terraform apply tfplan
```

From here an approved policy change needs no edit to any code. It reaches AWS on the next run. In a large account, allow several minutes per plan and space scheduled runs so one finishes before the next starts.

**Done when** a scheduled run with no approved change since the last one plans no change in any workspace, and step 6's check still passes.

## Step 9: Full control only: declare your own groups' rules through the rules module

Skip this step unless you use Full control. Under Full control Xshield also narrows a broad rule in a security group of your own. The workspace that owns the group makes that change, through `modules/aws-security-group-rules`. Do this once for each group, before a change that narrows it is approved, and add the workspace to the chain of step 7.

```terraform
provider "xshield" {}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
}

module "web_rules" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws-security-group-rules?ref=v0.2.0"

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

Give each rule a key you keep, and add a `moved` block for each rule resource you already have, so nothing in AWS changes. Rules declared inline, as `aws_security_group_rule` resources, or outside Terraform move with `import` and `removed` blocks instead, as [`full-control-adopt/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/full-control-adopt) shows.

**Done when** the first plan shows each rule as moved or imported, destroys no rule, and adds only `terraform_data.xshield_routed`. Apply it.

When a change is approved, run the enforcement workspace, then this workspace. When a change is reverted, run this workspace first. Keep every rule in the map, before and after Xshield leaves it out: if you delete one yourself first, the workloads that still rely on it lose that traffic early.

## Step 10: Watch it

Copy [`monitor/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/monitor) into a workspace of its own, set `cloud_account_id` and `region`, and plan it on a schedule. It manages no resources. Each problem is a warning that says what to do. To stop a pipeline on a problem, name it in `fail_on`:

```terraform
fail_on = ["drift_high", "never_applied"]
```

**Done when** a plan of the monitor, taken after step 6's check has passed, prints no warning.

## Later

- **To stop enforcing**, undeploy the policy in Xshield and keep running the enforcement workspace: it removes the groups. Do not run `terraform destroy` on it, or remove its module block.
- **To move the account back to connector delivery**, the enforcement workspace uses [`leave/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/leave), and the workspaces with a group lookup need a change first.
- **If the enforcement workspace's state is lost**, add [`recovery/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/recovery) before any other apply.

The [Xshield documentation](https://docs.xshield.colortokens.com/developer-tools/terraform/pipeline-delivery-aws-reference) gives the procedure for each of these, and for every failure and message a run can show.

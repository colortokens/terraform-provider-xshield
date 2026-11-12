# Pipeline-rendered enforcement for AWS

Apply Xshield segmentation policy through your own Terraform pipeline. Xshield renders every rule; these modules create exactly what it lists, and report back what was applied.

## Who writes what

Xshield decides everything that is enforced: which groups exist, every rule in them, what carries each group, and under Full control which rule of a group of your own is left out. None of that is written in your code. Your code carries it to AWS, through the modules below.

**Shipped with the provider.** You write none of it. Call each module by its `source`, at the tag of the provider release you run. The modules use the provider's own data sources and receipt resource, which the [provider's README](../../README.md#enforcing-aws-policy-through-your-own-pipeline) lists.

| Directory | What it is |
|--|--|
| `modules/aws` | The enforcement module. One block per AWS account and region. |
| `modules/aws-group-lookup` | Gives a database, function or service the group it must attach. Reads only SSM. |
| `modules/aws-security-group-rules` | Declares one of your own security group's rules through Full control. A group no approved change applies to plans as its code declares it. |

**To copy and fill in.** New code in your repository, complete but for its inputs.

| Directory | What it is |
|--|--|
| `enforcement/` | An enforcement workspace, ready to copy. |
| `enforcement-role/` | The role the enforcement workspace assumes, with only the permissions below. |
| `monitor/` | A workspace that reports each enforcement problem as a named check, and stops a plan on the ones you choose. |
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
| `apprunner/` | A workspace that owns an App Runner service, with a VPC connector of its own that carries the group Xshield gave it beside its own. |
| `full-control/` | A workspace that owns a security group Xshield narrows under Full control, and declares the group's rules through `modules/aws-security-group-rules`. |

**Another way to deliver.**

| Directory | What it is |
|--|--|
| `connector-managed/` | The other way: author policy in HCL and let the Xshield connector enforce it. |

### What a person does

| Where | What a person does | How often |
|--|--|--|
| A new enforcement workspace | Copies `enforcement/`, creates its role from `enforcement-role/`, sets the API key on the runner and runs the workspace on a schedule: step 1. | Once for each account and region |
| The workspace that owns a database, function or service | Adds the lookup module and puts its output in the resource's list of groups: step 2. | Once for each resource |
| A workspace that declares an instance's or an interface's security groups | Adds `ignore_changes`: step 3. | Once for each such instance or interface |
| Under Full control, the workspace that owns a security group Xshield narrows | Configures the `xshield` provider and moves the group's rules into the rules module: step 4. | Once for each group |
| A new monitor workspace | Copies `monitor/` and runs it on a schedule: step 5. | Once for each account and region |

After that, a policy change approved in Xshield needs no edit to any of this code. It reaches AWS on the next run of the enforcement workspace. It also needs the next run of an owning workspace when it changes which groups a resource of that workspace carries, or leaves out a rule of a group that workspace owns.

## Quickstart

### 1. Enforcement workspace: one per account and region

```hcl
provider "aws" {
  region = "us-east-1"
  assume_role { role_arn = "arn:aws:iam::123456789012:role/xshield-enforcement" }
}

provider "xshield" {} # credentials from XSHIELD_* environment variables

module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws?ref=vX.Y.Z"
}
```

The modules ship in the provider's repository, under `examples/enforcement-snapshot/modules/`. Set `ref` to the tag of the provider release you run, so the module and the provider match.

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
| `XSHIELD_PRIVATE_KEY` or `XSHIELD_PRIVATE_KEY_PATH` | The PEM private key, or a path to it |

The role the workspace assumes needs only these actions; `enforcement-role/` creates it, limiting every group and rule change to resources tagged `ManagedBy = ColorTokens`:

| Purpose | Actions |
|--|--|
| Groups and rules | `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupEgress`, `ec2:RevokeSecurityGroupIngress`, `ec2:RevokeSecurityGroupEgress`, `ec2:ModifySecurityGroupRules`, `ec2:CreateTags`, `ec2:DeleteTags` |
| Instance attachments | `ec2:ModifyNetworkInterfaceAttribute` |
| Reads | `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`, `ec2:DescribeNetworkInterfaces` |
| Directory | `ssm:PutParameter`, `ssm:DeleteParameter`, `ssm:GetParameter`, `ssm:GetParametersByPath`, `ssm:AddTagsToResource`, `ssm:RemoveTagsFromResource`, `ssm:ListTagsForResource` on `arn:aws:ssm:*:*:parameter/colortokens/*`, and `ssm:DescribeParameters`, which takes no parameter ARN |

Deleting a group that an AWS-managed interface still references, such as one Lambda has not yet removed, fails until AWS removes that interface; the next apply then succeeds. Grant `ec2:DetachNetworkInterface` and `ec2:DeleteNetworkInterface` if you would rather Terraform removed such interfaces itself.

### 2. Databases, functions and services: the workspace that owns them attaches the group

The enforcement workspace attaches each instance's group itself. Terraform has no separate attachment for an RDS instance, Aurora cluster, Lambda function, Managed Flink application or App Runner service, so the workspace that owns one adds the group to the resource's own list.

That workspace declares nothing of Xshield's. The enforcement workspace creates the group and every rule in it, such as the `rds/orders-db/in/tcp/5432/10.20.1.11/32` rule in the plan above, and writes the group's ID to the SSM parameter `/colortokens/v1/rds/orders-db/security-groups`. The lookup module reads that parameter by the resource's handle:

```hcl
module "orders_db_xshield" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-group-lookup?ref=vX.Y.Z"

  handle                 = "rds/orders-db"
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
- `own_security_group_ids` makes the plan fail, rather than the apply, when the database's own groups and Xshield's are more than AWS allows on it.
- The output shows Xshield's group in this workspace's plan, under `Changes to Outputs`, when it arrives and when it leaves.

`database/` is this workspace in full. Its `xshield.tf` holds everything the team adds, and its `main.tf` is the team's own code with the one changed line marked.

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

### 3. Instances whose Terraform declares their security groups

Nothing to do for instances no workspace manages one by one, such as Auto Scaling instances. If a workspace sets `vpc_security_group_ids` on an `aws_instance`, or `security_groups` on an `aws_network_interface`, that list is authoritative and removes the group the enforcement workspace attached. Tell Terraform to leave it alone:

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

### 4. Full control: declare your own groups' rules through the rules module

Skip this step unless you use Full control. Under Full control Xshield also narrows a broad rule in a security group of your own, such as `0.0.0.0/0` on port 443. In pipeline delivery this goes through your code. The enforcement workspace changes only Xshield's own groups, so a rule leaves a group of yours in a plan of the workspace that owns the group. That workspace declares the group's rules through `modules/aws-security-group-rules`, and the module leaves a rule out once Xshield says it is safe to.

A person does this step once for each group. From then on Xshield decides which of the declared rules are created, and an approved change needs no edit to the workspace.

In the workspace that owns the group:

1. Configure the `xshield` provider as in step 1. The API key's user must be able to read cloud snapshots.
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
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-security-group-rules?ref=vX.Y.Z"

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

The plan then shows the rule as `has moved to`, and nothing in AWS is added or destroyed. The one resource it adds is `terraform_data.xshield_routed`, the [record the module keeps in state](modules/aws-security-group-rules/README.md#the-record-kept-in-state).

`full-control/` is this workspace in full. Its `xshield.tf` holds everything the team adds, and its `main.tf` is the team's own code with the two changes marked.

What a plan of this workspace shows:

- A group no approved change applies to plans exactly as its code declares it. The module reads nothing from Xshield for that group.
- When an approved change applies to the group, the module asks Xshield which declared rules to keep. A group is matched by its name and its VPC, so a group of the same name in another VPC is not affected. A rule is matched by what it allows: its direction, protocol, ports and source or destination. Its key plays no part in the match.
- A rule Xshield narrows stays in the plan until every workload that still needs it carries a `ct-cohort-` group that keeps that access. The enforcement workspace creates those groups, so run it first. The next plan of this workspace then removes the rule, and no workload loses access part-way.
- Until this workspace has applied, the group keeps its broad rule. `xshield_enforcement_status` reads `waiting` while the change waits for this workspace, and the monitor reports `owner_apply_overdue` when the wait passes `max_owner_apply_age`.

Keep every rule in the map, before and after Xshield leaves it out. If you delete a rule yourself before Xshield leaves it out, the workloads that still rely on it lose that traffic early. If the change is reverted, the rule comes back only while your code still declares it. Do not add a rule that gives back traffic a change took away: every workload in the group gets that traffic again.

A plan of this workspace fails when Xshield cannot be reached. A plan that stops with `Invalid count argument` or `Invalid for_each argument` in the module is explained under [When something goes wrong](#when-something-goes-wrong). Policies that check the plans of workspaces that own such groups are provided by ColorTokens separately: see [`policies/`](policies/README.md).

### 5. Monitor

Run `monitor/` as a workspace of its own, on a schedule. It reads the status of one account and region and reports each thing that is wrong as a named check, in words a reviewer without portal access can act on.

| Problem | Reported when |
|---|---|
| `drift_high` | The cloud differs from what was applied and access may be wider than approved. |
| `workload_not_enforced` | Xshield could not write a group for a workload. The message names it and the reason. |
| `apply_overdue` | Newer approved policy has waited longer than `max_apply_age` (24h) for an enforcement run. The message counts and lists what is waiting. |
| `never_applied` | Published policy has never been applied, for longer than `max_apply_age`. |
| `owner_apply_overdue` | A Full control change has waited longer than `max_owner_apply_age` (24h) for the workspace that owns a customer security group. |
| `pipeline_stopped` | No enforcement plan has run for longer than `max_run_gap` (72h). Raise it if that pipeline runs only on a change. |
| `drift_not_evaluated` | Xshield has not looked for drift since the last apply, for longer than `max_unobserved_age` (24h). No finding then means nobody looked. |
| `port_not_narrowed` | A port is still deployed in Xshield after the Full control change that narrowed its customer security group was reverted. |
| `drift_medium` | The cloud differs in a way the next enforcement apply restores. Not warned by default. |
| `unpublished` | Xshield has published nothing here: the wrong tenant, or an account that is not onboarded. Not warned by default. |

Every check only warns, so the monitor never blocks a pipeline unless you ask it to. Choose what it warns about with `warn_on`. Name a problem in `fail_on` and the plan stops on it, with the same message, and no OPA or Sentinel:

```hcl
fail_on = ["drift_high", "never_applied"]
```

The `problems` output carries the same report by name, for a job that posts it somewhere. The workspace manages no resources, so `-detailed-exitcode` says nothing about it. To learn from an exit code whether approved policy is applied, plan the *enforcement* workspace on a schedule with `-detailed-exitcode`: 2 means it has something to apply, which is approved policy not yet applied or a resource it manages changed in the cloud.

Where policy sets decide what blocks a run, use the example policy in [`policies/`](policies/README.md) in place of `fail_on`. [Exit codes and what stops a pipeline](#exit-codes-and-what-stops-a-pipeline) compares the choices.

## Exit codes and what stops a pipeline

Terraform reports a problem as a warning or as an error, and only an error stops a run.

| Terraform reports | What it does to the run | Where these examples use it |
|--|--|--|
| A failed `check` block | A warning. The plan and the apply go ahead, and the exit code is the same as without it. | Every check in `monitor/`. `xshield_published` and `interfaces_have_room` in `modules/aws`. `directory_entry` in `modules/aws-group-lookup`. |
| A failed precondition or postcondition | An error. The plan stops with exit code 1, so nothing is applied. | In `modules/aws`: a snapshot for another account or region, and groups in the account while nothing is published. In `modules/aws-group-lookup`: a handle without a kind, and more groups than the resource can carry. In `monitor/`: a problem named in `fail_on`. |
| A failed variable validation, or an error from a provider | An error, as above. | A reserved tag key in `modules/aws`. A name `monitor/` does not know in `warn_on` or `fail_on`. Xshield cannot be reached. |

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
- 0 means AWS holds what was last applied, as far as Terraform can see. A rule someone adds to an Xshield group is not a resource Terraform manages, so it never shows here. Only the monitor reports it, as `drift_high`.
- 1 means the plan stopped. [When something goes wrong](#when-something-goes-wrong) lists the messages.

A workspace that exports outputs, as `enforcement/` does, returns 2 on its first plan even while nothing is published, because the outputs are new. Apply once and it returns 0.

### The monitor workspace

The monitor manages no resources, so `-detailed-exitcode` says nothing about enforcement there, and every monitor check only warns. To stop a pipeline on a problem, choose one of these:

- **`fail_on`.** The monitor's `problems` output has a precondition that fails while a problem named in `fail_on` is present. The plan then stops with exit code 1 and prints the message the check prints. A name in `fail_on` stops the plan even when `warn_on` leaves it out.
- **The example policy.** [`policies/`](policies/README.md) holds one example policy, `xshield-checks`, for the workspace that runs the monitor, written for Sentinel and for OPA. It reads the check results Terraform records in the plan and reports every failed check whose name starts with `xshield_`. It ships advisory. Raise its enforcement level and any failed Xshield check stops the run. `warn_on` then chooses which problems can stop it, because a problem `warn_on` leaves out fails no check. Use it in place of `fail_on` where policy sets decide what blocks a run. Outside HCP Terraform and Terraform Enterprise, `opa eval --fail-defined` over the JSON plan exits non-zero when an Xshield check failed.
- **The `problems` output.** It carries the same report by name, for a job of your own that reads it and decides.

Policies for groups under Full control are provided by ColorTokens separately.

## Stop enforcing

`terraform destroy` on the enforcement workspace is not the way to stop enforcing. Neither is deleting the `module "xshield_enforcement"` block. Both delete Xshield's groups and tell Xshield nothing:

- Xshield keeps the last receipt, so `xshield_enforcement_status` reads as it did before. The missing groups show only as drift findings, once the cloud connector observes the account.
- Under Full control the `ct-cohort-` groups are deleted too. They keep the access a workload still needs after a broad rule left one of your own groups, so those workloads lose that access.
- AWS refuses to delete a group that a database, function or service still carries, so the destroy can fail part-way.

To stop enforcing, withdraw the policy in Xshield by undeploying it, for the workloads concerned or for the whole account. Keep the enforcement workspace and keep running it. Xshield publishes a version without the groups, and the workspace removes them:

- An instance's group is detached and deleted by the enforcement run.
- A database's, function's or service's group goes in two steps. First its directory entry stops listing the group, so the workspace that owns the resource detaches it on its next apply. Xshield lists the group as `withdrawing`, and keeps its rules, until it sees the group detached. A later version then drops the group, and the enforcement run deletes it.
- When no group is left the run still sends its receipt, so Xshield knows the removal was applied.

When the account moves to connector delivery, nothing is destroyed either. Follow `leave/`: its `removed` block makes Terraform stop managing the groups, rules, attachments and directory parameters, and leaves them in the account for the cloud connector. Remove the outputs that read the module in the same change, or the configuration no longer validates.

If `terraform destroy` was run by mistake, run the enforcement workspace again. It creates what the current version lists and sends a new receipt.

## Try it locally

The module tests mock both providers, so they need no tenant or AWS account. Build the provider from this repository and point Terraform at it. Run these from this directory:

```bash
(cd ../.. && go build -o examples/enforcement-snapshot/bin/ .) && sed "s|/absolute/path/to/examples/enforcement-snapshot|$PWD|" dev.tfrc > .dev.tfrc
```

```bash
cd modules/aws && TF_CLI_CONFIG_FILE=../../.dev.tfrc terraform init -backend=false && TF_CLI_CONFIG_FILE=../../.dev.tfrc terraform test
```

`modules/aws-group-lookup`, `modules/aws-security-group-rules`, `monitor/`, `database/`, `apprunner/` and `full-control/` have tests too. Run them the same way from their own directories; from `monitor/`, `database/`, `apprunner/` and `full-control/` the file is `../.dev.tfrc`. `recovery/` and `handover/` hold a file for the enforcement workspace, not a workspace, so their tests run in a copy of one: each test file says how.

## What happens if

Each row is a mistake or a failure: what it does in AWS, what Xshield shows, and how to put it right. `state`, notices and drift findings are what `xshield_enforcement_status` returns. Names such as `drift_high` are the monitor's problems. The messages a plan prints are listed under [When something goes wrong](#when-something-goes-wrong).

| What happens | In AWS | What Xshield shows | To put it right |
|--|--|--|--|
| Policy is approved in Xshield and the enforcement workspace has not run | No change. AWS keeps the policy last applied. | `state` is `pending`, or `unapplied` when nothing was applied before, with what is waiting and since when. The monitor reports `apply_overdue` or `never_applied` after `max_apply_age`. | Run the enforcement workspace. |
| The enforcement pipeline stops running | No change. Nothing newly approved is applied. | `last_checked_at` stops moving, whatever `state` says. The monitor reports `pipeline_stopped` after `max_run_gap`. | Start the pipeline again. The monitor runs as a workspace of its own, so it still reports. |
| Under Full control, the workspace that owns a group has not applied | The group keeps its broad rule, so the change is not in force for that group. No workload loses access. | `state` is `waiting`, and a `changeSetHeld` notice says what the change waits for. The monitor reports `owner_apply_overdue` after `max_owner_apply_age`. | Apply the workspace that owns the group. If it does not declare the group through `modules/aws-security-group-rules` yet, do step 4 first. |
| A Full control change is reverted while a port it narrowed stays deployed | Your group again allows more than the port's policy. | A `portNotNarrowed` notice for each workload. The monitor reports `port_not_narrowed`. | Deploy the port again and approve its change, or undeploy the port. |
| A workspace sets an instance's or an interface's security groups without `ignore_changes` | That workspace's next apply takes Xshield's groups off the instance or interface. Under Full control this can cut access a `ct-cohort-` group kept for the workload. | A `memberUnattached` drift finding of high severity. The monitor reports `drift_high`. | Add `ignore_changes` as in step 3, then run the enforcement workspace to attach the groups again. |
| A lookup handle is misspelt | The resource gets no Xshield group. Nothing else changes. | Xshield reports the resource as `memberUnattached`. The monitor reports `drift_high`. | Correct the handle. Set `warn_when_unlisted = true` to have the plan warn when a handle has no entry. |
| Resources are written by hand in place of `modules/aws` | Whatever the code declares is created. | Xshield refuses the receipt unless the resources are exactly the snapshot's, so the version is not recorded as applied. | Use `modules/aws`. |
| The AWS provider points at another account or region than the snapshot is for | Nothing. The plan stops. | Nothing is applied or confirmed. | Point the AWS provider at the account and region the snapshot is for. |
| Xshield has published nothing for the account and region: the account is not yet set to pipeline delivery, has no deployed policy, or the `xshield` provider points at another tenant | Nothing is created and no receipt is sent. The run warns through the `xshield_published` check. If the account already holds groups Xshield rendered, the plan stops and does not remove them. | The tenant the provider reads shows `state` as `unpublished`. The monitor reports `unpublished` only when `warn_on` names it. A tenant that does hold policy for the account sees no run, so that policy keeps waiting. | Check in Xshield that the account is set to pipeline delivery and has a deployed policy. Check `XSHIELD_SERVER_URL` and the API key. |
| Xshield cannot be reached, or refuses the API key | Nothing. The enforcement plan fails, and so does the plan of every workspace that uses `modules/aws-security-group-rules`. A workspace that uses only `modules/aws-group-lookup` is not affected: the lookup reads only SSM. | Nothing changes. | Check `XSHIELD_SERVER_URL` and the key's role, then run again. |
| `terraform destroy` is run on the enforcement workspace, or its module block is deleted | Xshield's groups are taken off instances and deleted, with their rules and directory parameters. Under Full control, workloads lose the access their `ct-cohort-` groups kept. | Nothing at first: Xshield keeps the last receipt. Drift findings follow once the cloud connector observes the account. | Run the enforcement workspace again. To stop enforcing, see [Stop enforcing](#stop-enforcing). |
| The enforcement workspace's state is lost | Nothing changes. The groups stay in place. | Nothing changes. Xshield still holds the last receipt. | Before any other apply, follow `recovery/`: its import blocks rebuild the state from the last receipt. The plan shows every resource as an import, with an in-place change on each group and each directory parameter: it sets attributes an import cannot read and writes each parameter again with the value it holds. No group, rule or attachment changes, and no receipt is sent. An instance in the last receipt that has since been terminated has no attachment left to import: the plan leaves it out and sends the receipt again without it. |
| The account moves to connector delivery and the enforcement workspace still runs | Nothing. The plan stops with `Xshield moved <account>/<region> to connector delivery`. | `state` is `handedOver`. | Replace the module block with `leave/leave.tf`, remove the outputs that read the module, apply once, then stop running the workspace. |
| A rule is removed from an Xshield group outside Terraform | The traffic the rule allowed is blocked until the next enforcement apply puts the rule back. | A `ruleMissing` drift finding of medium severity. The monitor reports `drift_medium`, which it does not warn about by default. | Run the enforcement workspace. |
| A rule is added to an Xshield group outside Terraform | The rule stays, and access is wider than approved. Terraform does not manage the rule, so no enforcement run removes it. | A `ruleUnmanaged` drift finding of high severity. The monitor reports `drift_high`. | Remove the rule by hand. |
| AWS refuses a rule during an enforcement apply | The apply fails. The group keeps its old rules, because new rules are created before old ones are removed. | No receipt is sent, so the version is not recorded as applied. | Fix what AWS refused, then run the workspace again. |
| A workload has no room for another security group, or its group would pass the quota of rules per security group | Nothing new is written for that workload. One that carries an Xshield group keeps it, with the rules last applied. One that carries none gets none. | An `assetRefused` or `groupRefused` notice with the reason, such as `NO_FREE_SLOT`. The monitor reports `workload_not_enforced`. | Free a slot on the workload's interfaces, or raise the quota. For a group over the rule quota, see `modules/aws/README.md`. |
| `snapshot_version` pins a version | The pinned version stays applied. | Xshield reports the account as `pending` while the pin is in place. | Remove the pin when the rollback is over. |
| The cloud connector has not observed the account since the last apply | Nothing. | `drift_evaluated` is false and no drift finding is listed, which means nobody looked. The monitor reports `drift_not_evaluated` after `max_unobserved_age`. | Check that the cloud connector's discovery is running. |

## When something goes wrong

| You see | It means | Do |
|--|--|--|
| `This snapshot is for A/R, but the AWS provider is configured for B/S` | The AWS provider points at another account or region than `cloud_account_id` or `region` | Point the AWS provider at the account the snapshot is for, or drop the inputs to use the provider's |
| `Cannot resolve the snapshot Xshield expects` | Xshield could not be reached as configured, or the API key's user cannot read cloud snapshots. An account with nothing published is not an error: the plan shows no change | Check `XSHIELD_SERVER_URL` and the key's role |
| Warning: `Xshield has published nothing for A/R, so this run creates nothing and sends no receipt` | The account is not yet set to pipeline delivery, has no deployed policy, or the provider reads another tenant or endpoint | If the account should have policy, check in Xshield that it is set to pipeline delivery and has a deployed policy, and check `XSHIELD_SERVER_URL` and the API key |
| `Xshield has published nothing for A/R, yet the account holds security groups Xshield rendered` | The provider reads another tenant or endpoint than the one that published the groups | Point the provider back at that tenant. Removing the module, as the message offers, deletes the groups and tells Xshield nothing, as `terraform destroy` does: to stop enforcing, see [Stop enforcing](#stop-enforcing) |
| `Xshield moved A/R to connector delivery` | The account's delivery is now the cloud connector, which keeps the groups this workspace created | Replace the module block with `leave/leave.tf`, remove the outputs that read the module, apply once, then stop running the workspace |
| `This provider version cannot apply this snapshot` | Xshield publishes a newer snapshot format | Upgrade the `colortokens/xshield` provider |
| `Xshield did not accept the apply receipt` | What was applied is not exactly what the snapshot lists | The details name the keys missing or unknown; use the enforcement module rather than hand-written resources |
| `Cannot read the changes Xshield made to customer groups in A/R` | Xshield could not be reached as configured, or the API key's user cannot read cloud snapshots. An account and region with nothing published is not an error: every group keeps the rules its code declares | Check `XSHIELD_SERVER_URL` and the key's role |
| `Invalid count argument` or `Invalid for_each argument` in a `aws-security-group-rules` module | An approved Full control change applies to a group with this name, and the plan cannot know the group's VPC or one of its declared rules until apply: the same run creates the VPC or a group a rule references, or the module has a `depends_on` with pending changes. Or a change applies to some group in the account and region, and this group's own name is not known until apply, as `name_prefix` gives it on the run that creates the group. The plan stops rather than declare a rule Xshield has left out | Apply the new VPC or group first, for example with `-target`, then plan again; or drop the module's `depends_on`. While no change is published for the account and region, no group stops here |
| `handle must be <kind>/<name>` | The lookup's handle has no kind | Use one of the handles in the table above |
| Warning: `Xshield lists no entry for <handle>`, with `warn_when_unlisted` set | The resource is new and Xshield has not yet discovered it, Xshield's policy gives it nothing to attach, Xshield refuses it, or the handle is misspelt | Nothing for a new resource. Otherwise compare the handle with the enforcement module's `directory_entries` output, and look for the resource among the `assetRefused` and `groupRefused` notices of `xshield_enforcement_status` |
| `tags cannot set ManagedBy or a key starting with ct:` | A tag would hide the group from the cloud connector | Choose another tag key |
| The `monitor` check names a workload with `NO_FREE_SLOT` | Its interfaces already carry as many groups as AWS allows | Free a slot, or raise the account's security groups per interface quota |
| `These network interfaces carry as many security groups as the account allows` | An interface filled up since Xshield last discovered it, so its new group was left off this run | Free a slot on the named interface, or raise the quota; the next run attaches it |
| `<handle> would carry N security groups of its own and M of Xshield's` | The owning workspace's own groups and Xshield's are more than AWS allows on the resource | Drop one of its own groups, or raise the quota where AWS allows it |

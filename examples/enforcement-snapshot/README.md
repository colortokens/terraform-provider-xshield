# Pipeline-rendered enforcement for AWS

Apply Xshield segmentation policy through your own Terraform pipeline. Xshield renders every rule; the modules in [`modules/`](../../modules/) create exactly what it lists and report back what was applied. You write no rule.

To set it up, follow the [step-by-step guide](../../docs/guides/aws-pipeline-enforcement.md). The [Xshield documentation](https://docs.xshield.colortokens.com/developer-tools/terraform/pipeline-delivery-aws) covers pipeline delivery in depth, including operations, recovery and troubleshooting.

## What is here

**Modules**, shipped with the provider. Call each by its `source`, at the tag of the provider release you run.

| Directory | What it is |
|--|--|
| [`modules/aws`](../../modules/aws/) | The enforcement module. One block per AWS account and region. |
| [`modules/aws-group-lookup`](../../modules/aws-group-lookup/) | Gives a database, function or service the group it must attach. Reads only SSM. |
| [`modules/aws-security-group-rules`](../../modules/aws-security-group-rules/) | Declares one of your own security group's rules under Full control. |

**Workspaces to copy and fill in.**

| Directory | What it is |
|--|--|
| `enforcement/` | An enforcement workspace. |
| `enforcement-role/` | The IAM role the enforcement workspace assumes, with only the permissions it needs. |
| `monitor/` | A workspace that reports each enforcement problem as a named check, and can stop a plan on the ones you choose. |
| `chain/` | A GitHub Actions workflow that runs the owners' workspaces after the enforcement workspace, in order, on a schedule. |
| `policies/` | An example Sentinel and OPA policy, `xshield-checks`, for the workspace that runs the monitor. |

**Files for one apply.** Each goes into the enforcement workspace for a single event, and is deleted afterwards.

| Directory | When |
|--|--|
| `handover/` | An account moves from cloud connector delivery to pipeline delivery. |
| `leave/` | An account moves back to cloud connector delivery. |
| `recovery/` | The enforcement workspace's state is lost. |

**Examples of workspaces you already have**, after the change Xshield needs. In each, `xshield.tf` holds what the team adds, and `main.tf` marks each changed line.

| Directory | What it is |
|--|--|
| `database/` | An RDS instance that attaches the group Xshield gave it beside its own. |
| `function/` | A Lambda function in a VPC, the same way. |
| `apprunner/` | An App Runner service, through a VPC connector of its own. |
| `full-control/` | A security group whose rules are declared through `modules/aws-security-group-rules`. |
| `full-control-adopt/` | Existing groups moved into that module with `import` and `removed` blocks. |
| `connector-managed/` | The other way to deliver: author policy in HCL and let the Xshield cloud connector enforce it. |

## Quickstart

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

`enforcement/` calls the module as `../../../modules/aws`, which exists only inside this repository. In your copy, change that `source` to the address above. The module needs no inputs: it enforces the account and region the AWS provider is configured for, and refuses a snapshot meant for any other.

Set the API key as secret environment variables on the runner:

| Variable | Value |
|--|--|
| `XSHIELD_SERVER_URL` | `https://<tenant>.colortokens.com` |
| `XSHIELD_TENANCY_ID`, `XSHIELD_USER_ID`, `XSHIELD_FINGERPRINT` | Shown with the API key under **Settings > API Keys** |
| `XSHIELD_PRIVATE_KEY` | The PEM private key itself, or `XSHIELD_PRIVATE_KEY_PATH` for a file holding it |

Then, as the [guide](../../docs/guides/aws-pipeline-enforcement.md) walks through:

- Workspaces that set an instance's or network interface's security groups add `ignore_changes`, so they do not take Xshield's group off.
- Workspaces that own a database, function, service or Auto Scaling group add the group lookup, as `database/` shows, and run after the enforcement workspace.
- Under Full control, workspaces that own a security group Xshield narrows declare its rules through the rules module, as `full-control/` shows.
- `monitor/` runs on a schedule and reports what needs attention.

After that, a policy change approved in Xshield needs no edit to any of this code. It reaches AWS on the next run.

## Stop enforcing

Do not run `terraform destroy` on the enforcement workspace, or delete its module block, to stop enforcing: both delete Xshield's groups and tell Xshield nothing. Undeploy the policy in Xshield instead, and keep running the enforcement workspace: it removes the groups. To move an account back to cloud connector delivery, use `leave/` in the order the [Xshield documentation](https://docs.xshield.colortokens.com/developer-tools/terraform/pipeline-delivery-aws-reference#stopping-enforcement-and-moving-to-connector-delivery) describes.

## Try it locally

The module tests mock both providers, so they need no tenant or AWS account. Build the provider from this repository and point Terraform at it. From this directory:

```bash
(cd ../.. && go build -o examples/enforcement-snapshot/bin/ .) && sed "s|/absolute/path/to/examples/enforcement-snapshot|$PWD|" dev.tfrc > .dev.tfrc
export TF_CLI_CONFIG_FILE="$PWD/.dev.tfrc"
(cd ../../modules/aws && terraform init -backend=false && terraform test)
```

The other modules and most workspaces here have tests too; run them the same way from their own directories. `make tftest` at the repository root runs them all.

# Pipeline-rendered enforcement for AWS

Apply Xshield segmentation policy through your own Terraform pipeline. Xshield renders every rule; these modules create exactly what it lists, and report back what was applied.

| Directory | What it is |
|--|--|
| `modules/aws` | The enforcement module. One block per AWS account and region. |
| `modules/group-lookup` | Gives a database, function or service the group it must attach. Reads only SSM. |
| `modules/security-group-rules` | Declares one of your own security group's rules through Full control. A group no approved change applies to plans as its code declares it. |
| `enforcement/` | An enforcement workspace, ready to copy. |
| `enforcement-role/` | The role the enforcement workspace assumes, with only the permissions below. |
| `database/` | A workspace that owns an RDS instance and attaches its Xshield group. |
| `apprunner/` | A workspace that owns an App Runner service, with a VPC connector of its own for its Xshield group. |
| `monitor/` | A `check` block that alerts on drift, stalled pipelines and refused workloads. |
| `recovery/` | Import blocks that rebuild a lost enforcement state from the last receipt. |
| `handover/` | Import blocks that take over the groups the cloud connector created, when an account moves to pipeline delivery. |
| `leave/` | A `removed` block that hands the account's groups to the cloud connector, when an account moves back to connector delivery. |
| `connector-managed/` | The other way: author policy in HCL and let the Xshield connector enforce it. |

## Quickstart

### 1. Enforcement workspace: one per account and region

```hcl
provider "aws" {
  region = "us-east-1"
  assume_role { role_arn = "arn:aws:iam::123456789012:role/xshield-enforcement" }
}

provider "xshield" {} # credentials from XSHIELD_* environment variables

module "xshield_enforcement" {
  source = "colortokens/enforcement/xshield//modules/aws"
}
```

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

The enforcement workspace attaches each instance's group itself. Terraform has no separate attachment for an RDS instance, Aurora cluster, Lambda function, Managed Flink application or App Runner service, so the workspace that owns one adds its group to the resource's own list:

```hcl
module "orders_db_xshield" {
  source = "colortokens/enforcement/xshield//modules/group-lookup"
  handle = "rds/orders-db"
}

resource "aws_db_instance" "orders" {
  identifier = "orders-db"
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

An App Runner service takes groups only through its VPC connector, and every service on a connector gets the connector's groups, so give each service a connector of its own: see `apprunner/`.

The lookup needs no Xshield credentials, only `ssm:GetParametersByPath` on `/colortokens/v1/*`. A resource Xshield lists no entry for gets an empty list, so its plan never depends on Xshield and shows nothing from it. A misspelt handle therefore attaches nothing, and Xshield reports the resource as `memberUnattached`. To have the plan warn whenever a handle has no entry, set `warn_when_unlisted = true`; the warning is then expected on the run that creates the resource, and for a resource Xshield's policy gives nothing to attach.

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

### 4. Monitor

Copy `monitor/` into any workspace, or run it on a schedule. It alerts when Xshield sees high-severity drift, when approved policy has waited more than a day for an apply, and when a workload could not be enforced, naming the workload and the reason.

## Try it locally

The module tests mock both providers, so they need no tenant or AWS account. Build the provider from this repository and point Terraform at it. Run these from this directory:

```bash
(cd ../.. && go build -o examples/enforcement-snapshot/bin/ .) && sed "s|/absolute/path/to/examples/enforcement-snapshot|$PWD|" dev.tfrc > .dev.tfrc
```

```bash
cd modules/aws && TF_CLI_CONFIG_FILE=../../.dev.tfrc terraform init -backend=false && TF_CLI_CONFIG_FILE=../../.dev.tfrc terraform test
```

## When something goes wrong

| You see | It means | Do |
|--|--|--|
| `This snapshot is for A/R, but the AWS provider is configured for B/S` | The AWS provider points at another account or region than `cloud_account_id` or `region` | Point the AWS provider at the account the snapshot is for, or drop the inputs to use the provider's |
| `Cannot resolve the snapshot Xshield expects` | Xshield could not be reached as configured, or the API key's user cannot read cloud snapshots. An account with nothing published is not an error: the plan shows no change | Check `XSHIELD_SERVER_URL` and the key's role |
| `Xshield has published nothing for A/R, yet the account holds security groups Xshield rendered` | The provider reads another tenant or endpoint than the one that published the groups | Point the provider back at that tenant; to remove the groups on purpose, remove the module |
| `This provider version cannot apply this snapshot` | Xshield publishes a newer snapshot format | Upgrade the `colortokens/xshield` provider |
| `Xshield did not accept the apply receipt` | What was applied is not exactly what the snapshot lists | The details name the keys missing or unknown; use the enforcement module rather than hand-written resources |
| `Cannot read the changes Xshield made to customer groups in A/R` | Xshield could not be reached as configured, or the API key's user cannot read cloud snapshots. An account and region with nothing published is not an error: every group keeps the rules its code declares | Check `XSHIELD_SERVER_URL` and the key's role |
| `Invalid count argument` or `Invalid for_each argument` in a `security-group-rules` module | An approved Full control change applies to a group with this name, and the plan cannot know the group's VPC or one of its declared rules until apply: the same run creates the VPC or a group a rule references, or the module has a `depends_on` with pending changes. The plan stops rather than declare a rule Xshield has left out | Apply the new VPC or group first, for example with `-target`, then plan again; or drop the module's `depends_on`. A group no change applies to never stops here |
| `handle must be <kind>/<name>` | The lookup's handle has no kind | Use one of the handles in the table above |
| Warning: `Xshield lists no entry for <handle>`, with `warn_when_unlisted` set | The resource is new and Xshield has not yet discovered it, Xshield's policy gives it nothing to attach, Xshield refuses it, or the handle is misspelt | Nothing for a new resource. Otherwise compare the handle with the enforcement module's `directory` output, and look for the resource among the `assetRefused` and `groupRefused` notices of `xshield_enforcement_status` |
| `tags cannot set ManagedBy or a key starting with ct:` | A tag would hide the group from the cloud connector | Choose another tag key |
| The `monitor` check names a workload with `NO_FREE_SLOT` | Its interfaces already carry as many groups as AWS allows | Free a slot, or raise the account's security groups per interface quota |
| `These network interfaces carry as many security groups as the account allows` | An interface filled up since Xshield last discovered it, so its new group was left off this run | Free a slot on the named interface, or raise the quota; the next run attaches it |
| `<handle> would carry N security groups of its own and M of Xshield's` | The owning workspace's own groups and Xshield's are more than AWS allows on the resource | Drop one of its own groups, or raise the quota where AWS allows it |

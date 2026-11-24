---
page_title: "Enforce Azure policy through your own pipeline"
description: |-
  Step by step: apply the network security groups Xshield renders for an Azure subscription through your own Terraform pipeline, and keep them applied.
---

# Enforce Azure policy through your own pipeline

Xshield renders the network security groups, and their rules, that an Azure subscription and region need, and the network interface or subnet each one goes on. Your pipeline applies them with the `azure` enforcement module shipped in this provider's repository, and tells Xshield what it applied. You write no rule.

Each step below says who does it, what to run, and how to tell it worked. Take them in order: each relies on the one before it. The module's [README](https://github.com/colortokens/terraform-provider-xshield/tree/main/modules/azure) explains where each group goes, and every message the module gives.

## Before you start

- An Xshield administrator has set the subscription to pipeline delivery through the Xshield API, which needs its cloud connector to be Read-Only. Xshield keeps it Read-Only while the subscription stays on pipeline delivery, so the connector never writes beside your pipeline.
- An Xshield API key for a pipeline user, created under **Settings > API Keys**. The user's role needs `READ_ENFORCEMENT_SNAPSHOT` and `CREATE_ENFORCEMENT_RECEIPT`, which the built-in ADMIN and USER roles have, and must cover every workload in the subscription.
- Terraform 1.7 or later, and the azurerm provider 4.81.0 or later.

Xshield's group goes on a network interface or subnet that carries none of yours, and Azure applies both a network interface's group and its subnet's, so where yours sits beside Xshield's, traffic passes only where both allow it. Where every network interface and subnet of a workload carries a group of yours, Xshield adds the workload's rules to your subnet's group instead, ahead of your rules and naming only that workload's addresses, and leaves your rules as they are. No workspace other than the enforcement workspace changes, except one that declares subnets inline in a virtual network, or the rules of such a group inline (step 3).

The module lives in the [`modules/azure`](https://github.com/colortokens/terraform-provider-xshield/tree/main/modules/azure) directory of this provider's repository. Every `source` below is pinned to the provider release this page was published with. If you run another release of the `colortokens/xshield` provider, set `ref` to its tag, so the module and the provider match.

## Step 1: Give the runner the API key

Set these as secret environment variables on the runner of every workspace that configures the `xshield` provider. Nothing secret goes in the code.

| Variable | Value |
|--|--|
| `XSHIELD_SERVER_URL` | `https://<tenant>.colortokens.com` |
| `XSHIELD_TENANCY_ID`, `XSHIELD_USER_ID`, `XSHIELD_FINGERPRINT` | Shown with the API key under **Settings > API Keys** |
| `XSHIELD_PRIVATE_KEY` | The PEM private key itself, or set `XSHIELD_PRIVATE_KEY_PATH` to a file holding it |

Give the azurerm provider its credentials through the `ARM_*` environment variables in the same way.

**Done when** the variables are set on each runner that step 4, step 5 and step 6 use.

## Step 2: Create the enforcement role, once per subscription

Whoever owns access control in the subscription applies [`enforcement-role-azure/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement-role-azure), with `pipeline_principal_ids` set to the object IDs of the service principal or managed identity your runner uses. Creating the role and its assignments takes Owner or User Access Administrator on the subscription. The role itself can write network security groups and their rules, network interfaces and subnets, and holds the join actions Azure checks when they change: no compute, identity or data access.

Azure has no condition that limits these writes to Xshield's own groups. Set `scopes` to the resource groups that hold your workloads' network interfaces and subnets, and your network security groups on those subnets, rather than leaving the role on the whole subscription. Associating a group rewrites the whole network interface or subnet, and Azure checks a join on every resource it links to where that resource is, so `scopes` must also hold the resource groups of linked resources, such as a hub's route tables.

**Done when** the apply prints `role_definition_id`.

## Step 3: Keep Xshield's groups on subnets your code declares

Azure keeps one network security group on each network interface and subnet, and the enforcement module sets Xshield's through an association resource. A workspace of yours that declares the same subnet keeps that association only if it declares the subnet as its own resource:

| Your workspace declares | What happens to Xshield's group |
|--|--|
| `azurerm_subnet` and `azurerm_network_interface` resources | Kept, including when you change them |
| Subnets inline in `azurerm_virtual_network`, as `subnet` blocks | Removed by your next apply of that workspace, even with no change to its code. Step 5's check reports `memberUnattached`, and the next enforcement apply puts the group back, so the two workspaces keep undoing each other. |
| An `azurerm_subnet_network_security_group_association` or `azurerm_network_interface_security_group_association` for a level that carries Xshield's group | The apply fails, saying an association already exists. Nothing changes. |

For each virtual network whose subnets hold workloads Xshield enforces, move every inline `subnet` block into an `azurerm_subnet` resource, with an `import` block so Terraform adopts the existing subnet rather than creating it, and leave the virtual network's `subnet` argument out:

```terraform
import {
  to = azurerm_subnet.app
  id = "/subscriptions/<subscription ID>/resourceGroups/network/providers/Microsoft.Network/virtualNetworks/main/subnets/app"
}

resource "azurerm_subnet" "app" {
  name                 = "app"
  resource_group_name  = "network"
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.20.1.0/24"]
}
```

**Done when** a plan of each such workspace shows no change to any subnet.

### Keep Xshield's rules in groups of yours that your code declares

Where every network interface and subnet of a workload carries a group of yours, the enforcement module adds the workload's rules to your subnet's group as `azurerm_network_security_rule` resources. The enforcement snapshot's `customer_network_security_groups` lists these groups. A workspace of yours that declares one of them with its rules inline, in `security_rule`, removes Xshield's rules at its next apply. For each such group, declare its rules through `xshield_azure_security_rules`, which gives back your rules with Xshield's ahead of them, and list the group's resource ID in the module's `customer_network_security_groups_in_code` in step 4:

```terraform
data "xshield_azure_security_rules" "app" {
  cloud_account_id          = "<subscription ID>"
  region                    = "eastus2"
  network_security_group_id = "/subscriptions/<subscription ID>/resourceGroups/network/providers/Microsoft.Network/networkSecurityGroups/app"
  declared_security_rules   = local.app_rules
}

resource "azurerm_network_security_group" "app" {
  name                = "app"
  resource_group_name = "network"
  location            = "eastus2"
  security_rule       = data.xshield_azure_security_rules.app.security_rules
}
```

That workspace configures the `xshield` provider, so give its runner the API key too (step 1). A group with no inline rules, or whose rules your code declares as `azurerm_network_security_rule` resources, needs nothing.

**Done when** a plan of each such workspace shows only Xshield's rules added to the group.

## Step 4: Create the enforcement workspace and apply it, once per subscription and region

Start from [`enforcement-azure/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement-azure). In your copy, change the module's `source` from `../../../modules/azure` to the repository address, or `terraform init` fails:

```terraform
provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
}

provider "xshield" {}

module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/azure?ref=v0.2.0"

  region = var.region
}

output "xshield_review" {
  value = module.xshield_enforcement.review
}
```

The module takes no policy input. `resource_provider_registrations = "none"` keeps azurerm from registering resource providers, which the enforcement role does not allow.

```shell
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Read the plan before you apply it. Each group is named `ct-policy-` and a hash of its network interface or subnet, or from the cloud account's security group name template when it has one, and `xshield_review` says in words where each group goes, for which workloads, and what its rules allow and deny. A workload you expect Xshield to enforce but that no group names is not in this version; step 5 says how to find out why. The apply creates Xshield's groups, associates each with its network interface or subnet, and sends the receipt last.

**Done when** a second `terraform plan -detailed-exitcode` returns `0`: Azure holds what Xshield published, and Xshield has the receipt. That does not yet show any workload carrying its group: step 5 does.

## Step 5: Check that each workload is enforced

The receipt says what your pipeline applied, not what each workload carries. That shows at the cloud connector's first observation after the apply. Read it in a workspace of its own, configured as in step 1, which manages no resources:

```terraform
data "xshield_azure_enforcement_status" "this" {
  cloud_account_id = "00000000-0000-0000-0000-000000000000"
  region           = "eastus2"
}

output "xshield_enforcement" {
  value = {
    state           = data.xshield_azure_enforcement_status.this.state
    drift_evaluated = data.xshield_azure_enforcement_status.this.drift_evaluated
    findings        = [for f in data.xshield_azure_enforcement_status.this.drift_findings : "${f.kind} ${coalesce(f.resource_name, f.resource, "-")}: ${f.detail}"]
    notices         = [for n in data.xshield_azure_enforcement_status.this.notices : "${n.code} ${coalesce(n.asset_name, n.group, n.asset_id, "-")}: ${n.message}"]
  }
}
```

```shell
terraform apply -auto-approve
terraform output xshield_enforcement
```

| Check | Success | When it is not |
|--|--|--|
| The observation | `state = "converged"` and `drift_evaluated = true` | `drift_evaluated = false`: no observation has followed the apply yet. Run the check again later. If it stays false, check that the cloud connector is running and can read the subscription. |
| Each workload | Azure shows Xshield's group on its network interface or subnet, and no finding or notice names it | `assetRefused`: the notice names the workload, the reason and what to change. A workload with no group and no notice: Xshield has not yet discovered it or generated its policy. |
| Every workload | Its **Policy status** in the Xshield portal reads **Synchronized** | Any notice says what keeps the workload from its policy. |

To see the group a network interface or subnet carries:

```shell
az network nic show --ids <network interface ID> --query networkSecurityGroup.id --output tsv
az network vnet subnet show --ids <subnet ID> --query networkSecurityGroup.id --output tsv
```

**Done when** `state` is `converged`, `drift_evaluated` is `true`, `findings` is empty, `notices` holds only those you have decided to accept, and every workload reads **Synchronized**.

## Step 6: Run it on a schedule and watch it

Xshield does not notify your pipeline when it publishes a version, so plan the enforcement workspace on a schedule, and apply when `terraform plan -detailed-exitcode` returns `2`. Add the `check` blocks of the [`xshield_azure_enforcement_status` example](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/data-sources/xshield_azure_enforcement_status) to a workspace of their own and plan it on a schedule too. Each warns, without failing the run, of a refused workload, high-severity drift, or a pipeline that has stopped resolving the version Xshield expects.

**Done when** a plan of that workspace, taken after step 5's check has passed, prints no warning.

## Later

| When | Do |
|--|--|
| You want to stop enforcing a workload | Undeploy its policy in Xshield and keep running the enforcement workspace: the next apply removes the association, then the group. Do not run `terraform destroy`, or remove the module block: both delete the groups while Xshield still expects them. |
| A plan fails because a network interface or subnet carries a group of yours | Azure removes an association by clearing whatever group its level carries, so the module will not remove Xshield's once yours is there. After the cloud connector's next observation, the `associationHeld` notice names it and the plan keeps it unchanged until the level carries no group of yours. |
| A rule appears in one of Xshield's groups that it did not publish | The next apply removes it. To keep such rules until a person removes them, set `enable_exclusive_rules = false` on the module, as its README describes. |
| The subscription moves back to connector delivery | Undeploy its workloads in Xshield and apply the version that withdraws Xshield's groups: Xshield moves the subscription only once the version it expects holds none. Once it has, the plan stops with `Xshield moved <subscription>/<region> to connector delivery`. Remove the module block, apply once, and stop running the workspace. The connector needs Read-Write access to enforce again, which Xshield allows only once the subscription is back on connector delivery; you can then remove the enforcement role's assignments. |
| The enforcement workspace's state is lost | `xshield_azure_enforcement_status` returns the Azure ID of each group and association the last receipt recorded, in `applied_network_security_groups`, `applied_interface_associations` and `applied_subnet_associations`, keyed as the module keys them. Import each with an `import` block to that address, set `snapshot_version` to `applied_version`, and apply. Remove the pin afterwards. |

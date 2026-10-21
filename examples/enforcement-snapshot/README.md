# Xshield + Terraform - working examples

Two supported approaches to driving Xshield policy from Terraform, both runnable.
Start with **[APPROACHES.md](APPROACHES.md)** for the comparison and how to choose.

| Approach | What it is |
|---|---|
| **Pipeline-Rendered Enforcement** (`pipeline-rendered/`) | Xshield compiles approved policy into a versioned snapshot; **your** Terraform renders the native security groups. ColorTokens holds no cloud credentials. |
| **Connector-Managed Enforcement** (`connector-managed/`) | Segments, templates, named networks and tag rules authored in HCL; the Xshield connector continues to enforce. Works on any runner, across every cloud and resource type the connector supports. |

```
.
├── APPROACHES.md                       # comparison and how to choose
├── demo-server/                        # dependency-free stand-in for the snapshot API
│
├── pipeline-rendered/                  # Pipeline-Rendered Enforcement
│   ├── enforcement-workspace/          #   SecOps-owned; renders groups + directory
│   │   └── iam-guardrails.md           #   REQUIRED SCP/IAM companion to Sentinel
│   ├── modules/ct-workload-lookup/     #   the only surface application teams touch
│   ├── app-workspace/                  #   example application-team consumption
│   ├── monitor-workspace/              #   read-only drift and convergence alerts
│   ├── azure-workspace/                #   same snapshot, Azure-native rendering
│   └── sentinel/                       #   governance policy set
│
└── connector-managed/                  # Connector-Managed Enforcement
                                        #   policy authoring + deployment trigger
```

## Pipeline-Rendered Enforcement in one screen

**SecOps (once per account x region):**

```hcl
data "xshield_enforcement_snapshot" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.region      # no version pin - converges to expected
}

module "ct_enforcement" { source = "..." , snapshot = ... }   # renders groups
```

**Application team (once per workload - or zero lines if it lives in your golden module):**

```hcl
module "ct" {
  source = "app.terraform.io/acme/ct-enforcement/aws//modules/ct-workload-lookup"
  tags   = local.workload_tags        # the tags the workload already carries
}

resource "aws_instance" "app" {
  vpc_security_group_ids = concat(var.base_sgs, module.ct.security_group_ids)
  tags                   = local.workload_tags
}
```

No ColorTokens provider, credential, endpoint, segment name, or policy version
appears in application code. Renaming segments in Xshield cannot break a caller.

## Run the Pipeline-Rendered demo offline

Self-contained: no AWS account, no live Xshield, no ColorTokens-issued
credentials. Requires Python 3, Go (to build the provider), and Terraform.

```bash
cd examples/enforcement-snapshot

# 1. a disposable signing key for the demo (the stand-in API does not verify it)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out demo-signing-key.pem

# 2. the snapshot API stand-in - standard library only, serves the bundled
#    sample snapshot on :8087
python3 demo-server/serve.py &

# 3. build the provider from source (from the repository root)
(cd ../.. && go build -o examples/enforcement-snapshot/bin/terraform-provider-xshield .)

# 4. point Terraform at that binary, then plan
#    (edit dev.tfrc first: dev_overrides requires an absolute path)
export TF_CLI_CONFIG_FILE="$PWD/dev.tfrc"
cd pipeline-rendered/enforcement-workspace
terraform init && terraform plan
```

Expected: **16 resources** - composed group security groups (`ct-seg-*`), marker
groups (`ct-ref-*`), a managed prefix list, 8 rules with stable content-derived
keys (e.g. `pci-db|in|tcp|5432-5432|group:pci-app` - note the peer is a *group
reference*, not an IP address), the SSM directory entries, and the apply
receipt that reports every created resource ID back to Xshield. There is **no
`tcp/22` rule**: an SSH block template suppressed it before the snapshot was
built.

A later policy change plans as exactly the rules it changes plus the receipt:
the snapshot version and hash live on the receipt, not on every resource.

Two plan warnings fire deliberately, demonstrating the guardrails:
`1 quarantined asset` (fail-secure - its policy is not rendered) and
`world-open ingress` (permitted, but surfaced as a decision worth reviewing).

## Multi-cloud

`pipeline-rendered/azure-workspace/` consumes the **identical** data source and
renders Azure-native constructs - Application Security Groups (for both
enforcement groups and markers), NSG rules that reference those ASGs, address
prefixes for off-cloud peers, and an App Configuration directory. No provider or
snapshot change is required.

It passes `terraform validate`. Unlike the AWS example it is **not** plan-proven
here, because `terraform plan` for Azure requires real subscription credentials -
treat it as a reviewed reference rendering rather than an executed one.

The rendering adapts to each platform's native primitives:

| | AWS | Azure |
|---|---|---|
| Membership | marker security groups | Application Security Groups (native) |
| Block semantics | absence of an allow | explicit deny rule with priority |
| Effective policy | union of all attached security groups | one NSG per NIC |
| Rule quota | 60 per direction, per group | ~1000 per NSG |

AWS was implemented first because its allow-only, union-evaluated model is the
most constrained, so the contract is proven against the tightest substrate. GCP
(target tags and service accounts, requiring no attachment wiring) and OCI
(NSG-to-NSG references) follow the same contract.

## Production checklist (Pipeline-Rendered)

- [ ] Delete `demo.auto.tfvars`; supply the same variables from your workspace.
- [ ] Set `demo_mode = false` (credentials come from the workspace role).
- [ ] Configure the remote state backend in `versions.tf` (one state per account x region).
- [ ] Deploy the SCP/IAM guardrails - **[iam-guardrails.md](pipeline-rendered/enforcement-workspace/iam-guardrails.md)**, including the bootstrap ordering.
- [ ] Attach the [Sentinel policy set](pipeline-rendered/sentinel/), with `ct-namespace-guard` **org-wide**.
- [ ] Agree the tag-key hierarchy (`tag_keys`) with your tagging standard, and mandate those keys at resource creation via SCP.
- [ ] Decide `max_quarantined_assets`, and whether strict lookup is on from day one.

## Current scope and considerations

- **AWS security groups are allow-only and union-evaluated.** The ColorTokens
  group carries the approved policy, but a workload's *effective* policy also
  includes any legacy groups still attached to it - addressed by the brownfield
  prune phase and kept closed by base-group hygiene thereafter.
- **Enforcement latency tracks your pipeline cadence** under Pipeline-Rendered
  Enforcement. Where changes must take effect immediately, Connector-Managed
  Enforcement is the faster path.
- **Sentinel is available on TFE and HCP Terraform.** On other runners the same
  checks can be expressed with OPA/conftest; we are happy to work through the
  equivalent for your toolchain.
- **Non-EC2 attachment** (RDS, Lambda, ECS, EKS pods) requires per-resource-type
  paths; EC2 and Auto Scaling launch templates are proven today.
- The bundled demo server logs but does **not verify** request signatures, and
  the key generated in step 1 is disposable. Production uses issued API keys (or
  OIDC workload identity, which is in development).
- The Pipeline-Rendered snapshot API is in development; Connector-Managed
  authoring works against the shipping product today.

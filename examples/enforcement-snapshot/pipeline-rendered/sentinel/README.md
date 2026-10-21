# ColorTokens Sentinel policy set

Governance for the Pipeline-Rendered Enforcement path. These are working,
reviewable policies - treat them as the starting point your platform team forks,
not a black box.

| Policy | Level | Attach to | What it stops |
|---|---|---|---|
| `ct-namespace-guard` | hard-mandatory | **every workspace** | Any workspace other than the account enforcement workspace creating or changing ColorTokens resources, directory parameters or apply receipts |
| `ct-no-world-open-admin-ports` | hard-mandatory | **every workspace** | Any ingress rule opening an administrative or data port to the internet - whatever the approved policy says |
| `ct-mass-delete-guard` | hard-mandatory | enforcement workspaces | A bad or empty snapshot removing an account's enforcement layer in one apply, unless teardown is explicitly approved |
| `ct-snapshot-integrity` | soft-mandatory | enforcement workspaces | A rendered rule that is not in the snapshot, or differs from it in direction, protocol, ports or peer; a snapshot rule left unrendered; a rule attached to a ColorTokens group outside the snapshot; a render that never reports back |
| `ct-version-integrity` | soft-mandatory | enforcement workspaces | Applying a plan built from a snapshot that is no longer the expected one |
| `ct-conformance-watch` | advisory | enforcement workspaces | Quarantined workloads passing unnoticed; also logs the version being applied |

`ct-common.sentinel` is a module the policies share.

## Fail or warn: choosing where a check lives

A check can live in five places, and they differ in who can override it:

| Mechanism | Effect | Override |
|---|---|---|
| Terraform `precondition` | The plan fails. Used for anything that would render wrongly, such as a peer type the configuration cannot render or a group over the account's rule quota. | None - fix the input. |
| Terraform `check` block | The plan warns and continues. Used for decisions worth a second look: quarantined workloads, world-open ingress. | Not needed. |
| Sentinel `hard-mandatory` | The run is blocked. | None. |
| Sentinel `soft-mandatory` | The run is blocked until a policy owner overrides it, which is recorded. | Policy owner. |
| Sentinel `advisory` | The result is shown and the run continues. | Not needed. |

To move a check between failing and warning, change its `enforcement_level` in
`sentinel.hcl`; to move it between Sentinel and Terraform, the condition is the
same - only the reach differs. Terraform checks run on any runner; Sentinel needs
HCP Terraform or Terraform Enterprise (on other runners, the same conditions can
be written for OPA/conftest against `terraform show -json`).

Keep `check` blocks free of their own data sources in the enforcement
workspace: Terraform re-reads such data sources at apply, so every plan would
show as having changes and no run would ever report "No changes". Drift checks
that need a data source live in `../monitor-workspace`.

## How these were tested

Each policy runs in the end-to-end lab against mocks generated from real plans
of the example workspaces, with expected pass and fail cases: a converged plan,
a policy opening SSH to the internet, a plan raced by a newer snapshot, a local
override widening every rule, a hand-written rule, and an empty snapshot with
and without teardown approval. To test them against your own plans, generate
mocks from `terraform show -json` (or download them from an HCP Terraform run)
and use `sentinel apply` or `sentinel test`.

Two Sentinel behaviours shaped how they are written:

- **`else` replaces undefined, not null.** The plan writes `null` for every
  unset attribute, so an expression such as `(tags else {}) contains "x"` is a
  runtime error for any resource with tags unset - and a runtime error fails the
  policy. Every optional attribute is read through `ct.value`.
- **Data sources read while planning are not in `resource_changes`.** They are
  in the plan's prior state, which is where `ct.snapshots` reads the snapshot.

## Before production

- `ct-version-integrity` needs the Sentinel `http` import enabled for the policy
  set, and network reachability to the snapshot API. Sentinel cannot compute the
  provider's request signature, so the expected-version endpoint must accept a
  bearer token for a principal that can only read it.
- `ct-mass-delete-guard` reads approval from the workspace's
  `ct_teardown_approved` Terraform variable. `tfrun.variables` exposes variable
  names but never values, so the approval cannot be read from there.
- `ct-snapshot-integrity` takes an optional `approved_vcs_repo`; set it to pin
  the enforcement workspace to its repository.
- Thresholds (`max_ct_deletes`, `admin_ports`, `max_quarantined`) and the API
  base, account and region are policy set parameters - set them per estate, do
  not edit the source.

## Sentinel is only half the control

These policies govern the Terraform path. They cannot govern the AWS control
plane - a console user with `ec2:AuthorizeSecurityGroupIngress` or
`ssm:PutParameter` bypasses all of them. The IAM/SCP counterpart in
`../enforcement-workspace/iam-guardrails.md` is **required**, not optional, and
the connector's drift report (see `../monitor-workspace`) is how a change made
around both is found.

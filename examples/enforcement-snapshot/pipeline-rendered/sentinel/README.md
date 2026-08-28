# ColorTokens Sentinel policy set

Governance for the Pipeline-Rendered Enforcement path. These are working,
reviewable policies - treat them as the starting point your platform team forks,
not a black box.

| Policy | Level | Attach to | What it prevents |
|---|---|---|---|
| `ct-namespace-guard` | hard-mandatory | **every workspace** | Any workspace other than the account enforcement workspace creating/editing ColorTokens resources or directory parameters |
| `ct-mass-delete-guard` | hard-mandatory | enforcement workspaces | A bad snapshot or removed module emptying an account's enforcement layer in one apply |
| `ct-provenance` | soft-mandatory | enforcement workspaces | Hand-written or forked rules masquerading as rendered policy |
| `ct-version-integrity` | soft-mandatory* | enforcement workspaces | Applying a plan built from a superseded snapshot (TOCTOU) |
| `ct-conformance-watch` | advisory | enforcement workspaces | Quarantined assets passing unnoticed; also logs the converged version |

\* advisory during brownfield coexistence, raised after the prune phase.

## Before production

- `ct-version-integrity` needs the Sentinel **`http` import** enabled for the
  policy set and network reachability to the snapshot API. If your edition or
  network policy forbids that, drop it and rely on `ct-provenance` plus the
  provider's own hash check - state the trade-off explicitly rather than assuming.
- `ct-provenance` has `allow_local_module` (default `false`). Leave it false in
  production, or the approved-source check can be satisfied by any module
  vendored into the repository.
- Run `sentinel test` with mocks generated from a real plan
  (`terraform show -json`) before attaching. These policies are written against
  the documented `tfplan/v2` and `tfconfig/v2` schemas but have not been executed
  in this repository.
- Parameters (`enforcement_workspace_pattern`, `max_ct_deletes`,
  `approved_module_source`, API base/account/region) are set per policy set in
  TFE - do not hardcode them in the source.

## Sentinel is only half the control

These policies govern the Terraform path. They cannot govern the AWS control
plane - a console user with `ssm:PutParameter` bypasses all of them. The IAM/SCP
counterpart in `../enforcement-workspace/iam-guardrails.md` is **required**, not
optional. Deploy both or your posture is defined by the weaker one.

# An example policy: act on the monitor's checks

The [monitor](../monitor) raises a named check for each problem it finds, such as policy that waits to be applied or
high-severity drift. `xshield-checks` is a policy for the workspace that runs the monitor. It reports every problem an
Xshield check of the plan raised, with the check's own message, and leaves every other check alone.

It ships advisory. Raise its enforcement level to stop a run on any failed Xshield check; the monitor's `warn_on` list
then chooses which problems can stop it. Use it in place of the monitor's `fail_on` list when policy sets are how your
organisation decides what blocks a run.

It is written twice, for Sentinel and for OPA, and reads only the plan's check results, so it is also a starting point
for a policy of your own.

## HCP Terraform and Terraform Enterprise

Create a policy set from one of these directories and attach it to the workspace that runs the monitor:

- `sentinel/` for a Sentinel policy set. `sentinel.hcl` sets the enforcement level.
- `opa/` for an OPA policy set. `policies.hcl` sets the enforcement level.

To make the check blocking, set its enforcement level to `soft-mandatory` (Sentinel) or `mandatory` (OPA).

## Other pipelines

Run the OPA policy against the JSON plan. This exits non-zero when an Xshield check failed:

```sh
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json
opa eval --fail-defined --format raw -d policies/opa -i plan.json 'data.terraform.policies.xshield_checks.warn[_]'
```

## Testing the policy

```sh
cd policies/sentinel && sentinel test
opa test policies/opa
```

## Policies for groups under Full control

When Xshield narrows one of your own security groups, further policies can check the plans of the workspaces that own
those groups. ColorTokens provides them separately; ask your ColorTokens contact.

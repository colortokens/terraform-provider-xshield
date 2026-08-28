# Two approaches to driving Xshield from Terraform

Both approaches are supported and both are represented in this bundle. They are
not mutually exclusive - many estates adopt Connector-Managed Enforcement first
and move accounts to Pipeline-Rendered Enforcement as pipeline maturity allows.
The choice is best made per account rather than per organisation.

| | **Pipeline-Rendered Enforcement** | **Connector-Managed Enforcement** |
|---|---|---|
| Directory | `pipeline-rendered/` | `connector-managed/` |
| Who writes the cloud rules | Your pipeline | The Xshield cloud connector |
| Cloud credentials held by ColorTokens | None | Connector requires cloud write access |
| Concrete security-group changes in the plan diff | Yes | No - policy intent is in code; rendered rules are not |
| Governable by Sentinel / OPA | Yes - the rules themselves | The policy objects |
| Terraform runner | TFE/HCP for the full gate story | Any runner (CLI, Atlantis, Spacelift, GitLab CI...) |
| Cloud coverage | Per-cloud rendering module (AWS and Azure included here) | Every cloud the connector supports today |
| Resource-type coverage | EC2 and Auto Scaling proven; RDS, Lambda, ECS, EKS need explicit attachment paths | Whatever the connector already handles |
| Time to enforce a change | Your pipeline cadence | Minutes |
| Emergency / break-glass | Needs a defined fast lane | Immediate, from the console |
| Availability today | Requires the snapshot API (in development) | Available now; deployment trigger via either variant below |

## Pipeline-Rendered Enforcement

**The case for it.** Enforcement becomes ordinary infrastructure-as-code. Every
security-group rule is created by your pipeline, from a signed and versioned
policy snapshot, visible as a plan diff in your own VCS and gated by your own
policy engine. ColorTokens holds no credentials into your cloud accounts and has
no write path to them; the only thing crossing the boundary is a read-only,
content-hashed policy document.

That matters most when a security organisation has determined that no third
party may hold write access to production cloud accounts, or when change control
requires every network rule to be a reviewable, attributable diff.

Two further properties are worth noting:

- **Scale-invariance.** Rendered rules reference security groups, prefix lists
  and ranges - never individual instance addresses. Autoscaling changes group
  membership, not rules, so scale events produce no pipeline activity and no
  enforcement gap.
- **Separation of duties.** Application teams resolve their groups from a
  tag-keyed directory and never touch a ColorTokens provider, credential, or
  segment name. Policy authorship stays with security; consumption stays with
  the application team.

**What to weigh.** AWS is the substrate proven furthest here, with Azure included
to demonstrate portability; other clouds follow the same contract but are not yet
built. The full governance story assumes Sentinel, which is available on TFE and
HCP Terraform. Enforcement latency tracks your pipeline cadence rather than being
immediate. And a workload that never attaches its resolved groups is unprotected
until conformance reporting flags it.

## Connector-Managed Enforcement

**The case for it.** Segments, templates, named networks and tag rules live in
version control, move through code review, and deploy from CI - while enforcement
continues along the path already running in production. There is no new
enforcement layer to operate, no dependency on a particular Terraform runner, and
coverage extends immediately to every cloud and resource type the connector
supports.

It is the right answer for estates that want policy under source control without
re-plumbing enforcement, that need sub-minute enforcement, that run Terraform
outside TFE/HCP, or that would simply rather not own the rendering layer.

**What to weigh.** The connector retains write access to the cloud account, and
the plan diff shows policy intent rather than the concrete security-group
changes - so this approach does not, by itself, satisfy a mandate that no
external party writes to production accounts.

### Two ways to trigger deployment

See `connector-managed/deploy.tf`.

- **Native `xshield_policy_deployment` resource (recommended).** Declarative,
  idempotent, visible in the plan, and reconciled like any other resource, built
  over the existing deployment API. This is the approach we would recommend, and
  we are happy to discuss timelines as part of your evaluation.
- **External helper invoked via `local-exec`.** Requires no platform change and
  can be adopted immediately.

Policy **authoring** works with today's provider in both cases; only the
deployment *trigger* requires one of the two variants. Teams can adopt the
authoring half now and add the trigger later.

## Choosing

A short way to decide:

- If a security mandate rules out third-party write access to your cloud
  accounts, or change control requires reviewable rule-level diffs -
  **Pipeline-Rendered Enforcement**.
- If you want policy under source control quickly, across every cloud and
  resource type, on the runner you already use - **Connector-Managed
  Enforcement**.
- If different accounts answer differently, run both. The two coexist, and an
  account can move from Connector-Managed to Pipeline-Rendered without
  re-authoring policy.

We are happy to work through the fit for specific accounts and to answer
questions on any of the code in this bundle.

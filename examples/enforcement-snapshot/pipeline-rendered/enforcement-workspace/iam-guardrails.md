# IAM / SCP guardrails - required, not optional

Sentinel governs the **Terraform path**. It does not govern the **AWS control
plane**. Both must be closed, or the weaker one defines your security posture.

Two namespaces need protecting.

## 1. The workload directory (`/colortokens/v1/*`)

This is the trust root of application-side resolution: it tells every future
workload which security groups to attach. A principal who can write it can
redirect production workloads onto groups of their choosing - a privilege
escalation path that no amount of Terraform policy can see.

Attach as an SCP at the OU containing your workload accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ColorTokensDirectoryIsWriteOnceByEnforcementRole",
    "Effect": "Deny",
    "Action": [
      "ssm:PutParameter",
      "ssm:DeleteParameter",
      "ssm:DeleteParameters",
      "ssm:AddTagsToResource",
      "ssm:RemoveTagsFromResource"
    ],
    "Resource": "arn:aws:ssm:*:*:parameter/colortokens/*",
    "Condition": {
      "ArnNotLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:role/ct-enforcement-*"
      }
    }
  }]
}
```

Read access stays open (every app workspace needs `ssm:GetParametersByPath` on
the prefix) - the directory holds security-group IDs, not secrets.

## 2. ColorTokens-managed resources (`ct-*` / `colortokens:managed`)

Prevents anyone outside the enforcement role from creating a lookalike security
group, or editing rules inside a rendered one between convergence runs.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ColorTokensManagedResourcesAreSingleWriter",
    "Effect": "Deny",
    "Action": [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:DeleteSecurityGroup",
      "ec2:ModifySecurityGroupRules"
    ],
    "Resource": "*",
    "Condition": {
      "StringEquals": { "aws:ResourceTag/colortokens:managed": "true" },
      "ArnNotLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:role/ct-enforcement-*"
      }
    }
  }]
}
```

> **Note on attachment:** `ec2:ModifyNetworkInterfaceAttribute` (attaching a
> group to an ENI) is deliberately **not** denied - application teams must be
> able to attach ColorTokens groups to their own workloads. What they cannot do
> is change what those groups *permit*.

## 3. Least-privilege for the enforcement role itself

The enforcement workspace's role needs only:

| Purpose | Actions |
|---|---|
| Render groups & rules | `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`, `ec2:Authorize*`, `ec2:Revoke*`, `ec2:ModifySecurityGroupRules`, `ec2:CreateTags`, `ec2:Describe*` |
| Prefix lists | `ec2:CreateManagedPrefixList`, `ec2:ModifyManagedPrefixList`, `ec2:DeleteManagedPrefixList`, `ec2:GetManagedPrefixListEntries` |
| Directory | `ssm:PutParameter`, `ssm:DeleteParameter`, `ssm:GetParameter*`, `ssm:AddTagsToResource` on `/colortokens/*` only |

It needs **no** compute, IAM, data, or networking permissions beyond the above.
ColorTokens itself holds none of this - the role belongs to your pipeline.

## 4. Bootstrap ordering (the part that bites)

1. Create the `ct-enforcement-<account>` role **first**, with the least-privilege
   policy above.
2. Apply the SCPs - they reference the role by ARN pattern, so the role must
   exist or every principal (including the enforcement role) is denied.
3. Vend the enforcement workspace bound to that role.
4. Attach `ct-namespace-guard` org-wide in Sentinel.
5. Only then onboard application workspaces.

Reverse this order and you will lock yourself out of the namespace.

## 5. What this still does not cover

Rule content inside a ColorTokens group can be edited by the enforcement role
itself (by definition). Out-of-band drift by that role is corrected on the next
convergence run, not prevented. If your posture requires continuous prevention
rather than periodic correction, pair this with AWS Config rules or
EventBridge-driven alerting on `colortokens:managed` resources - noted honestly
rather than claimed as solved.

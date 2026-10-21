# ct-workload-lookup

Resolves the ColorTokens security groups a workload must attach, using only the
tags it already carries.

```hcl
module "ct" {
  source = "app.terraform.io/acme/ct-enforcement/aws//modules/ct-workload-lookup"
  tags   = local.workload_tags
}

resource "aws_instance" "app" {
  vpc_security_group_ids = concat(var.base_sgs, module.ct.security_group_ids)
  tags                   = local.workload_tags
}
```

For autoscaling, put the same `vpc_security_group_ids` on the **launch template**
- every scaled-out instance is then enforced at birth with no pipeline involved.

## Inputs

| Name | Default | Notes |
|---|---|---|
| `tags` | *(required)* | The workload's tags - the only input app teams supply |
| `tag_keys` | `["environment","application","tier"]` | Org hierarchy order; set once in your golden module |
| `directory_prefix` | `/colortokens/v1` | Namespace the enforcement workspace publishes |
| `strict` | `true` | `false` only for a deliberate, time-boxed migration |

## Outputs

`security_group_ids` · `group` · `resolved_path`

## Behaviour worth knowing

- **Deepest match wins** - `env/app/tier` beats `env/app` beats `env`, mirroring
  segment hierarchy so the most-specific segment governs.
- **Strict key order** - a missing middle key stops path building; it can never
  silently collapse to a deeper path and bind the wrong groups.
- **Fail closed** - no match is a hard plan error, not an unprotected deploy.
  The error names every path tried and the action SecOps must take.
- **No ColorTokens coupling** - no provider, credential, endpoint, segment name,
  or policy version. Renaming segments upstream cannot break you.

## Requirements

Read access to the directory namespace:
`ssm:GetParametersByPath` on `arn:aws:ssm:*:*:parameter/colortokens/*`.

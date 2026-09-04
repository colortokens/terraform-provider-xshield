# Deploying is a separate step from describing policy. Templates and segments say
# what should be allowed; nothing reaches a firewall until a deployment runs.

# 1. Turn on enforcement for the assets in question. A deployment does nothing on
#    an asset whose enforcement is off, and says nothing about it.
data "xshield_assets" "payroll_db" {
  criteria = "application = 'payroll' AND role = 'db' AND environment = 'prod'"
}

resource "xshield_asset" "payroll_db" {
  for_each = toset(data.xshield_assets.payroll_db.ids)

  # Assets are imported rather than created; asset_name and type come from the API.
  asset_name = data.xshield_assets.payroll_db.assets[index(data.xshield_assets.payroll_db.ids, each.key)].asset_name
  type       = data.xshield_assets.payroll_db.assets[index(data.xshield_assets.payroll_db.ids, each.key)].type

  inbound_enforcement = true
}

# 2. Deploy the whole asset in test mode first. Test deploys the rules but logs
#    what would be blocked rather than blocking it.
resource "xshield_policy_deployment" "payroll_db_inbound" {
  criteria  = data.xshield_assets.payroll_db.criteria
  direction = "inbound"
  mode      = "test"
  comment   = "Managed by Terraform"

  depends_on = [xshield_asset.payroll_db]
}

# Deploying individual ports instead of the whole asset. This is a
# micro-deployment: the tenant has to permit it and every matched asset has to
# support it, which xshield_assets reports as micro_deployment_compatible.
resource "xshield_policy_deployment" "payroll_db_enforce_https" {
  criteria  = data.xshield_assets.payroll_db.criteria
  direction = "inbound"

  reviewed = {
    "TCP:443" = {
      mode          = "enforce"
      target_assets = "all"
    }
  }

  # Only the "*" key means anything here; the backend ignores any other.
  unreviewed = {
    "*" = { mode = "test" }
  }

  depends_on = [xshield_policy_deployment.payroll_db_inbound]
}

# Above zero means intent has moved on since the deployment ran.
output "still_to_deploy" {
  value = xshield_policy_deployment.payroll_db_enforce_https.ports_pending_deployment
}

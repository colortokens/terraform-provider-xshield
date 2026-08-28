# Values for the bundled OFFLINE demo (local stand-in API, no AWS account
# needed). Delete this file for real use and supply the same variables from your
# workspace/tfvars - the .tf files require no edits.

demo_mode = true

xshield_server_url       = "http://localhost:8087"
xshield_tenancy_id       = "demo-tenant"
xshield_user_id          = "ct-enforcement-bot"
xshield_fingerprint      = "demo"
xshield_private_key_path = "../../demo-signing-key.pem"

cloud_account_id = "123456789012"
region           = "us-east-1"
vpc_id           = "vpc-1"

# The bundled sample snapshot deliberately contains one quarantined asset so the
# fail-secure warning is visible in the demo plan.
max_quarantined_assets = 0

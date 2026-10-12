data "xshield_segments" "all" {}

# Segments whose auto-sync is enforcing rather than testing.
output "enforcing" {
  value = [
    for s in data.xshield_segments.all.segments : s.tag_based_policy_name
    if s.inbound_auto_sync_deployment_mode == "enforce"
  ]
}

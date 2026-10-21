# Resolve the policy Xshield expects this account and region to enforce. No
# version is set, so the configuration stays static while policy changes.
data "xshield_enforcement_snapshot" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

# Each rule carries a stable key derived from its content, which keeps
# resource addresses unchanged when the snapshot is reordered.
output "rule_keys" {
  value = [for r in data.xshield_enforcement_snapshot.this.rules : r.key]
}

output "converging_to" {
  value = "${data.xshield_enforcement_snapshot.this.version} (${data.xshield_enforcement_snapshot.this.content_hash})"
}

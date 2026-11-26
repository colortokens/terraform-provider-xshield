#!/usr/bin/env bash
# Runs terraform test in every module and example that has tests, against a provider built from this
# checkout. Both providers are mocked, so no tenant or AWS account is needed.
#
# recovery/, recovery-azure/, handover/, handover-azure/ and modules/aws/apply-order/ hold files for a workspace rather than a workspace,
# so each runs in a copy set up as its test file says. modules/aws/apply-order/upgrade needs the module
# version upgraded from, which is not in this repository, so it is left to run by hand.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
root=$PWD
snapshot=examples/enforcement-snapshot

scratch=$(mktemp -d)
cleanup() {
  rm -rf "$scratch" "$root/$snapshot"/.tftest-*
}
trap cleanup EXIT

go build -o "$scratch/bin/" .
cat >"$scratch/dev.tfrc" <<EOF
provider_installation {
  dev_overrides {
    "colortokens/xshield" = "$scratch/bin"
  }
  direct {}
}
EOF
export TF_CLI_CONFIG_FILE="$scratch/dev.tfrc"
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"
mkdir -p "$TF_PLUGIN_CACHE_DIR"

# A copy of a workspace file sits beside the original, so its ../../../modules sources still resolve.
copy_beside() {
  local name=$1
  shift
  local dir="$root/$snapshot/.tftest-$name"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp -R "$@" "$dir/"
  echo "$snapshot/.tftest-$name"
}

dirs=()
for d in modules/*/ "$snapshot"/*/; do
  d=${d%/}
  case $(basename "$d") in recovery | recovery-azure | handover | handover-azure) continue ;; esac
  [ -d "$d/tests" ] && dirs+=("$d")
done
dirs+=("$(copy_beside recovery "$snapshot/enforcement/main.tf" "$snapshot/recovery/recovery.tf" "$snapshot/recovery/tests")")
dirs+=("$(copy_beside recovery-azure "$snapshot/enforcement-azure/main.tf" "$snapshot/recovery-azure/recovery.tf" "$snapshot/recovery-azure/tests")")
dirs+=("$(copy_beside handover "$snapshot/enforcement/main.tf" "$snapshot/handover/handover.tf" "$snapshot/handover/tests")")
dirs+=("$(copy_beside handover-azure "$snapshot/enforcement-azure/main.tf" "$snapshot/handover-azure/handover.tf" "$snapshot/handover-azure/tests")")

apply_order="$scratch/apply-order"
mkdir -p "$apply_order"
cp modules/aws/*.tf modules/aws/apply-order/apply_order_override.tf "$apply_order/"
cp -R modules/aws/apply-order/tests "$apply_order/"
dirs+=("$apply_order")

failed=()
for d in "${dirs[@]}"; do
  label=${d#"$scratch/"}
  echo "::group::$label"
  if (cd "$d" && { out=$(terraform init -backend=false -input=false -no-color 2>&1) || { echo "$out"; false; }; } &&
    terraform test -no-color); then
    echo "::endgroup::"
  else
    echo "::endgroup::"
    echo "::error::terraform test failed in $label"
    failed+=("$label")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "terraform test failed in: ${failed[*]}" >&2
  exit 1
fi
echo "terraform test passed in ${#dirs[@]} directories"

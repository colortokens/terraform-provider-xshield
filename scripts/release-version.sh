#!/usr/bin/env bash
# Keeps every version a reader copies from the docs on one release:
#   - `version = "X.Y.Z"` directly under `source = "colortokens/xshield"`
#   - `?ref=vX.Y.Z` on a `terraform-provider-xshield//modules/...` source
#
#   release-version.sh set 0.3.0   rewrite them all to 0.3.0
#   release-version.sh check 0.3.0 fail unless they all read 0.3.0
#   release-version.sh check       the same, against the highest vX.Y.Z tag, the latest release
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

usage() {
  echo "usage: $0 set <version> | check [<version>]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
cmd=$1
version=${2:-}
version=${version#v}

if [ -z "$version" ]; then
  [ "$cmd" = check ] || usage
  tag=$(git tag --list 'v[0-9]*' --sort=-v:refname | grep -v -- - | head -n 1)
  if [ -z "$tag" ]; then
    echo "no release tag found; fetch tags or pass a version" >&2
    exit 1
  fi
  version=${tag#v}
fi

if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "not a semantic version: $version" >&2
  exit 2
fi

files=()
while IFS= read -r f; do files+=("$f"); done < <(git ls-files -- '*.md' '*.tf' '*.tmpl')

provider_re='(source\s*=\s*"colortokens/xshield"(?:[ \t]*\n[ \t]*|,[ \t]*)version\s*=\s*")([0-9X][^"]*)(")'
module_re='(terraform-provider-xshield//modules/[A-Za-z0-9_-]+\?ref=v)([^"\s)]+)'

case $cmd in
set)
  VERSION=$version perl -0pi -e "
    s{$provider_re}{\${1}\$ENV{VERSION}\${3}}g;
    s{$module_re}{\${1}\$ENV{VERSION}}g;
  " "${files[@]}"
  echo "set every published reference to $version; run 'make docs' to regenerate docs/"
  ;;
check)
  found=$(perl -0ne "
    while (m{$provider_re}g) { print \"\$ARGV: provider version \$2\n\" }
    while (m{$module_re}g) { print \"\$ARGV: module ref v\$2\n\" }
  " "${files[@]}")
  if [ -z "$found" ]; then
    echo "found no published version reference; has the pattern drifted from the docs?" >&2
    exit 1
  fi
  unstampable=$(grep -nE 'terraform-provider-xshield//|[vV]?[xX]\.[yY]\.[zZ]' -- "${files[@]}" |
    grep -vE 'terraform-provider-xshield//modules/[A-Za-z0-9_-]+\?ref=v[0-9]' || true)
  if [ -n "$unstampable" ]; then
    echo "these references are not in a form 'set' rewrites; write them as" >&2
    echo "  github.com/colortokens/terraform-provider-xshield//modules/<name>?ref=v<released version>" >&2
    echo "$unstampable" >&2
    exit 1
  fi
  stale=$(grep -Ev "(provider version |module ref v)${version//./\\.}\$" <<<"$found" || true)
  if [ -n "$stale" ]; then
    echo "these references are not $version; run: scripts/release-version.sh set $version && make docs" >&2
    echo "$stale" >&2
    exit 1
  fi
  echo "every published reference reads $version ($(wc -l <<<"$found" | tr -d ' ') found)"
  ;;
*)
  usage
  ;;
esac

#!/usr/bin/env bash
# Pull a new build into this repo safely.
#
#   ./update.sh ~/Downloads/mcp-gateway-w5.zip
#
# Extracts over the current checkout, leaving .git and .venv alone, then shows
# exactly what changed. Run from the repo root.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: ./update.sh PATH_TO_ZIP" >&2
  exit 2
fi

zip_path="$1"
repo="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$zip_path" ]; then
  echo "no such file: $zip_path" >&2
  echo "check the exact name - browsers rename duplicates:" >&2
  ls -1t "$(dirname "$zip_path")"/mcp-gateway*.zip 2>/dev/null | head -5 >&2
  exit 1
fi

if [ ! -d "$repo/.git" ]; then
  echo "refusing to run: $repo is not a git repo" >&2
  exit 1
fi

if ! git -C "$repo" diff --quiet || ! git -C "$repo" diff --cached --quiet; then
  echo "you have uncommitted changes. Commit or stash them first:" >&2
  git -C "$repo" status --short >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$zip_path" -d "$tmp"

src="$tmp/mcp-gateway"
[ -d "$src" ] || src="$tmp"

# "src/." copies the contents including dotfiles such as .gitignore. The
# archive contains no .git or .venv, so nothing in your repo is clobbered.
# cp rather than rsync: rsync is not installed everywhere, and a missing
# binary here would half-apply an update.
cp -R "$src"/. "$repo"/

echo
echo "updated from $(basename "$zip_path")"
echo
git -C "$repo" status --short
echo
echo "next: ./check.sh, then git add . && git commit"

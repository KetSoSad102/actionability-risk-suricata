#!/usr/bin/env bash
set -euo pipefail

# Reproducible by default. Override explicitly when testing another revision:
# UPSTREAM_REF=<commit-or-tag> ./scripts/fetch_full_upstream_rules.sh
UPSTREAM_REF="${UPSTREAM_REF:-73d86b249635215f0dee05dc38a32d49c8b1810c}"
UPSTREAM_DIR="upstream/ruling-the-unruly"

mkdir -p upstream
if [ ! -d "$UPSTREAM_DIR/.git" ]; then
  git clone --no-checkout https://github.com/Koen1999/ruling-the-unruly.git "$UPSTREAM_DIR"
fi

git -C "$UPSTREAM_DIR" fetch --depth 1 origin "$UPSTREAM_REF"
git -C "$UPSTREAM_DIR" checkout --detach FETCH_HEAD

cp "$UPSTREAM_DIR/improved.rules" rules/improved-full-upstream.rules
cp "$UPSTREAM_DIR/original.rules" rules/original-full-upstream.rules
cp "$UPSTREAM_DIR"/*.lua rules/
git -C "$UPSTREAM_DIR" rev-parse HEAD > rules/upstream-version.txt

echo "Fetched full upstream rules at $(git -C "$UPSTREAM_DIR" rev-parse HEAD)"
echo "Full upstream rules need their Lua files and Suricata Lua path configuration."

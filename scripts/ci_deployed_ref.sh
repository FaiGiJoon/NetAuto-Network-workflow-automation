#!/bin/sh
# Prints the commit that is currently on the devices (Git tag "deployed").
# No tag yet = first run: prints nothing, so the plan adds everything.
# That is safe because every command the plan writes is "create or update".
set -eu
git fetch --quiet --force origin 'refs/tags/*:refs/tags/*' 2>/dev/null || true
git rev-parse -q --verify "refs/tags/${1:-deployed}^{commit}" 2>/dev/null || true

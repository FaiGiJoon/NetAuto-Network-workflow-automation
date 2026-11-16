#!/bin/sh
# Moves the Git tag "deployed" to the commit that is now on the devices,
# and keeps the old one as "previous-deployed" (the default rollback target).
#   sh scripts/ci_mark_deployed.sh <commit>
# Needs GIT_PUSH_TOKEN: a project access token with write_repository.
set -eu
new="$1"
old="$(git rev-parse -q --verify 'refs/tags/deployed^{commit}' 2>/dev/null || true)"

if [ -z "${GIT_PUSH_TOKEN:-}" ]; then
  echo "ERROR: GIT_PUSH_TOKEN is not set, so the 'deployed' tag cannot move."
  echo "Without it the next plan cannot see removals. Set it in Settings > CI/CD > Variables."
  exit 1
fi

git tag -f deployed "$new"
refs="refs/tags/deployed"
if [ -n "$old" ] && [ "$old" != "$new" ]; then
  git tag -f previous-deployed "$old"
  refs="$refs refs/tags/previous-deployed"
fi
# shellcheck disable=SC2086
git push -f "https://oauth2:${GIT_PUSH_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" $refs
echo "deployed -> $new${old:+ (previous-deployed -> $old)}"

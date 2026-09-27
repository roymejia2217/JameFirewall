#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$PROJECT_ROOT/scripts/validate_commit_range.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git_init() {
  local repo="$1"
  git init -q -b main "$repo"
  git -C "$repo" config user.name "Governance Fixture"
  git -C "$repo" config user.email "fixture@example.invalid"
}

commit_file() {
  local repo="$1"
  local file="$2"
  local content="$3"
  local subject="$4"
  local body="$5"

  printf '%s\n' "$content" > "$repo/$file"
  git -C "$repo" add "$file"
  git -C "$repo" commit -q -m "$subject" -m "$body"
}

run_validator() {
  local repo="$1"
  local base="$2"
  local head="$3"

  (
    cd "$repo"
    EVENT_NAME=pull_request     BASE_SHA="$base"     HEAD_SHA="$head"     PR_AUTHOR=roymejia2217     HEAD_BRANCH=feat/governance-fixture     HEAD_REPOSITORY=example/JameFirewall     REPOSITORY=example/JameFirewall       bash "$VALIDATOR"
  )
}

assert_rejected() {
  local name="$1"
  shift
  if "$@"; then
    echo "Expected commit-range governance to reject: $name" >&2
    exit 1
  fi
}

REPO="$TMP/repo"
git_init "$REPO"

commit_file "$REPO" root.txt root   "chore(core): initialize governance fixture"   "Create the deterministic repository fixture used by branch governance tests."
BASE0="$(git -C "$REPO" rev-parse HEAD)"

git -C "$REPO" switch -q -c feat/probe
commit_file "$REPO" feature.txt feature   "feat(core): add fixture feature"   "Add a conventional feature commit before synchronizing the base branch."
FEATURE="$(git -C "$REPO" rev-parse HEAD)"

git -C "$REPO" switch -q main
commit_file "$REPO" main.txt main   "fix(core): advance fixture base"   "Advance the fixture base branch so the topic branch requires synchronization."
BASE1="$(git -C "$REPO" rev-parse HEAD)"

git -C "$REPO" switch -q feat/probe
git -C "$REPO" merge -q --no-ff main -m "Merge branch 'main' into feat/probe"
SYNC_HEAD="$(git -C "$REPO" rev-parse HEAD)"
run_validator "$REPO" "$BASE1" "$SYNC_HEAD"

git -C "$REPO" switch -q main
git -C "$REPO" switch -q -c feat/missing-body
printf '%s\n' invalid > "$REPO/invalid.txt"
git -C "$REPO" add invalid.txt
git -C "$REPO" commit -q -m "fix(ci): omit required body"
BAD_BODY="$(git -C "$REPO" rev-parse HEAD)"
assert_rejected "normal commit without body" run_validator "$REPO" "$BASE1" "$BAD_BODY"

git -C "$REPO" switch -q -C feat/tampered "$FEATURE"
git -C "$REPO" merge -q --no-commit --no-ff main
printf '%s\n' tampered > "$REPO/tampered.txt"
git -C "$REPO" add tampered.txt
git -C "$REPO" commit -q -m "Merge branch 'main' into feat/tampered"
TAMPERED="$(git -C "$REPO" rev-parse HEAD)"
assert_rejected "merge commit with extra tree changes" run_validator "$REPO" "$BASE1" "$TAMPERED"

git -C "$REPO" switch -q -C foreign "$BASE0"
commit_file "$REPO" foreign.txt foreign   "feat(core): create foreign history"   "Create a commit that is intentionally absent from the protected base history."
FOREIGN="$(git -C "$REPO" rev-parse HEAD)"

git -C "$REPO" switch -q -C feat/foreign "$BASE1"
git -C "$REPO" merge -q --no-ff foreign -m "Merge branch 'foreign' into feat/foreign"
FOREIGN_MERGE="$(git -C "$REPO" rev-parse HEAD)"
assert_rejected "merge whose second parent is not base history"   run_validator "$REPO" "$BASE1" "$FOREIGN_MERGE"

printf 'commit range governance adversarial contract: ok\n'

#!/usr/bin/env bash
set -euo pipefail

commitlint() {
  npm exec --no -- commitlint --verbose
}

release_commitlint() {
  npm exec --no -- commitlint --config commitlint.release.config.cjs --verbose
}

assert_rejected() {
  local name="$1"
  local message="$2"

  if printf '%s\n' "$message" | commitlint; then
    echo "Expected Commitlint to reject: $name" >&2
    exit 1
  fi
}

valid_message=$'feat(ui): add canonical application icon\n\nUse the approved multi-resolution application identity in the Windows package.'
valid_body_and_footer=$'fix(ci): preserve runtime evidence\n\nKeep the packaged runtime evidence attached to the protected Windows acceptance lane.\n\nRefs: #2'
valid_release_prep=$'chore(release): prepare changelog 0.3.0\n\nConsolidate validated Towncrier fragments into the governed release changelog.'
release_message='chore(main): release 0.2.0'
long_body="$(printf 'x%.0s' {1..101})"

printf '%s\n' "$valid_message" | commitlint
printf '%s\n' "$valid_body_and_footer" | commitlint
printf '%s\n' "$valid_release_prep" | commitlint

assert_rejected 'missing body' 'feat(ui): add canonical application icon'
assert_rejected 'body below minimum length' $'fix(ci): preserve evidence\n\nToo short.'
assert_rejected 'missing type' $'Update package identity\n\nDescribe the package identity change for the supported Windows workflow.'
assert_rejected 'unknown type' $'unknown(ui): update package identity\n\nDescribe the package identity change for the supported Windows workflow.'
assert_rejected 'bracket scope' $'fix[ui]: update package identity\n\nDescribe the package identity change for the supported Windows workflow.'
assert_rejected 'uppercase subject' $'feat(ui): Add package identity\n\nDescribe the package identity change for the supported Windows workflow.'
assert_rejected 'subject with period' $'feat(ui): add package identity.\n\nDescribe the package identity change for the supported Windows workflow.'
assert_rejected 'body without leading blank' $'fix(ui): update package identity\nDescribe the package identity change for the supported Windows workflow.'
assert_rejected 'body line over 100 characters' "fix(ci): preserve evidence

${long_body}"

assert_rejected 'release commit under the normal profile' "$release_message"

printf '%s\n' "$release_message" | release_commitlint

#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${EVENT_NAME:?EVENT_NAME is required}"
: "${BASE_SHA:?BASE_SHA is required}"
: "${HEAD_SHA:?HEAD_SHA is required}"
: "${PR_AUTHOR:=}"
: "${HEAD_BRANCH:=}"
: "${HEAD_REPOSITORY:=}"
: "${REPOSITORY:=}"

release_subject_regex='^chore\(main\): release [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
release_bot_email='41898282+github-actions[bot]@users.noreply.github.com'
release_branch='release-please--branches--main--components--JameFirewall'

normal_commitlint() {
  local sha="$1"
  git show -s --format='%B' "$sha" |
    npm exec --prefix "$PROJECT_ROOT" --no -- commitlint       --config "$PROJECT_ROOT/.commitlintrc.json" --verbose
}

release_commitlint() {
  local sha="$1"
  git show -s --format='%B' "$sha" |
    npm exec --prefix "$PROJECT_ROOT" --no -- commitlint       --config "$PROJECT_ROOT/commitlint.release.config.cjs" --verbose
}

validate_release_commit() {
  local sha="$1"
  local author_email
  local subject

  author_email="$(git show -s --format='%ae' "$sha")"
  subject="$(git show -s --format='%s' "$sha")"

  test "$author_email" = "$release_bot_email" || {
    echo "Release commit author is not github-actions[bot]: $author_email" >&2
    exit 1
  }
  [[ "$subject" =~ $release_subject_regex ]] || {
    echo "Release commit subject is not canonical SemVer release metadata: $subject" >&2
    exit 1
  }

  release_commitlint "$sha"
}

validate_sync_merge() {
  local sha="$1"
  local parents_line
  local actual_tree
  local expected_tree
  local -a parents

  parents_line="$(git show -s --format='%P' "$sha")"
  read -r -a parents <<< "$parents_line"
  test "${#parents[@]}" -eq 2 || {
    echo "Synchronization commit must have exactly two parents: $sha" >&2
    exit 1
  }

  git merge-base --is-ancestor "${parents[1]}" "$BASE_SHA" || {
    echo "Synchronization commit second parent is not in base history: $sha" >&2
    exit 1
  }

  if ! expected_tree="$(git merge-tree --write-tree --no-messages "${parents[0]}" "${parents[1]}")"; then
    echo "Synchronization commit is not a clean automatic merge: $sha" >&2
    exit 1
  fi
  expected_tree="${expected_tree%%$'\n'*}"
  actual_tree="$(git show -s --format='%T' "$sha")"

  test "$actual_tree" = "$expected_tree" || {
    echo "Synchronization commit contains changes beyond the automatic base merge: $sha" >&2
    exit 1
  }

  echo "Accepted structural base-sync merge: $sha"
}

validate_range() {
  local sha
  local parent_count
  local -a commits

  mapfile -t commits < <(git rev-list --reverse "$BASE_SHA..$HEAD_SHA")
  test "${#commits[@]}" -gt 0 || {
    echo "Commit range is empty: $BASE_SHA..$HEAD_SHA" >&2
    exit 1
  }

  for sha in "${commits[@]}"; do
    parent_count="$(git show -s --format='%P' "$sha" | awk '{print NF}')"
    case "$parent_count" in
      1)
        normal_commitlint "$sha"
        ;;
      2)
        test "$EVENT_NAME" = "pull_request" || {
          echo "Merge commits are not accepted on $EVENT_NAME events: $sha" >&2
          exit 1
        }
        validate_sync_merge "$sha"
        ;;
      *)
        echo "Unsupported commit topology with $parent_count parents: $sha" >&2
        exit 1
        ;;
    esac
  done
}

if [ "$EVENT_NAME" = "pull_request" ] &&
   [ "$PR_AUTHOR" = "github-actions[bot]" ] &&
   [ "$HEAD_REPOSITORY" = "$REPOSITORY" ] &&
   [ "$HEAD_BRANCH" = "$release_branch" ]; then
  mapfile -t release_commits < <(git rev-list --reverse "$BASE_SHA..$HEAD_SHA")
  test "${#release_commits[@]}" -eq 1 || {
    echo "Release Please PR must contain exactly one generated release commit." >&2
    exit 1
  }
  validate_release_commit "${release_commits[0]}"
elif [ "$EVENT_NAME" = "push" ]; then
  author_email="$(git show -s --format='%ae' "$HEAD_SHA")"
  subject="$(git show -s --format='%s' "$HEAD_SHA")"
  if [ "$author_email" = "$release_bot_email" ] &&
     [[ "$subject" =~ $release_subject_regex ]]; then
    validate_release_commit "$HEAD_SHA"
  else
    validate_range
  fi
else
  validate_range
fi

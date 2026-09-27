# Contributing to JameFirewall

JameFirewall treats contribution metadata as part of the engineering record, but it does not invent
a private formatting system where an established convention already exists.

## Commit messages

Commit messages follow **Conventional Commits 1.0.0** and are enforced by pinned Commitlint. The
repository uses the conventional grammar rather than inventing headings inside commit bodies:

```text
type(scope): subject

A meaningful body explaining the change.

Optional-Trailer: value
```

JameFirewall deliberately uses a stricter Conventional Commits profile. Every human or agent
commit requires a body of at least 20 characters, separated from the header by a blank line.
Headers are limited to 72 characters and body/footer lines to 100 characters. Conventional types
and the repository scope vocabulary are enforced by Commitlint. Trailers remain optional and, when
present, require the conventional leading blank line.

The commit body is prose, not a miniature pull-request template. Conventional Commits does not
define `What`, `Why`, or other body headings, so the repository does not fabricate them. The
body should explain context that is not already obvious from the subject and diff.

Release Please is the only typed exception: its generated commit is header-only
`chore(main): release <SemVer>`. CI may select the restricted release profile only when the pull
request comes from the canonical Release Please branch in this repository and the commit author is
`github-actions[bot]`. The normal profile still rejects the same header-only message from humans
or agents.

Reference: https://www.conventionalcommits.org/en/v1.0.0/

## Pull request title

Pull request titles use the Conventional Commits header grammar. The repository validates them
with `amannn/action-semantic-pull-request`; unlike commits, PR titles do not have a commit body.
The allowed title types and scopes are repository-specific extensions of the published convention.

## Pull request description

Pull request descriptions follow the principles in **Google Engineering Practices — Writing good
CL descriptions**: state what is changing and why, and include context or limitations that are not
obvious from the diff. GitHub's own pull-request guidance also recommends templates that capture
purpose, related issues, and testing information.

References:

- https://google.github.io/eng-practices/review/developer/cl-descriptions.html
- https://docs.github.com/en/pull-requests/reference/managing-and-standardizing-pull-requests
- https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository

The repository therefore requires exactly four level-two sections, in this order:

1. `What`
2. `Why`
3. `Testing`
4. `Related issues`

The headings are intentionally plain English, unnumbered, and free of decorative emoji. Additional
detail belongs inside those sections using paragraphs or lower-level headings.

`What`, `Why`, and `Testing` must contain substantive content rather than a placeholder.
`Related issues` must be explicit; use GitHub closing keywords when applicable or write `None.`
when no tracked issue exists.

## What is not part of the PR body contract

The body does not contain a manual release-type field, a self-attested quality checklist, or a
mandatory architecture/TDD section.

Those concerns have stronger machine-verifiable authorities:

- release impact comes from Conventional Commits and Release Please;
- tests, lint, typing, Windows acceptance, and packaging evidence come from required CI;
- architecture and design quality are evaluated by code review and repository-specific tests;
- merge eligibility comes from GitHub rulesets and required status checks.

Duplicating those facts as checkboxes would create a second, weaker source of truth.

## Language

Repository contribution metadata is written in English so public history remains consistent and
searchable. The automated contract enforces the canonical English headings; prose quality and
language remain review concerns because language-detection heuristics are not deterministic enough
to be a merge gate.


## Published branch lifecycle

A published agent branch is append-only. After its first push, contributors and agents must not
rewrite its history with `git push --force`, `git push --force-with-lease`, or an equivalent
non-fast-forward update. GitHub enforces that rule remotely through the
`agent-branch-immutability` ruleset; local hooks are not the authority.

If `main` advances while a pull request is open, use GitHub's native **Update branch** merge
operation instead of rebasing the published branch. The resulting synchronization merge commit is
accepted only when Git proves all of the following: it has exactly two parents, its second parent
belongs to the current base history, and its tree is byte-for-byte identical to the automatic merge
computed by `git merge-tree --write-tree`. Any manual content hidden inside that merge commit is
rejected.

Normal commits remain subject to the full Conventional Commits + Commitlint body contract. The
final merge into `main` remains rebase-only, so the protected default branch preserves linear
history even though a topic branch may contain a structurally verified synchronization merge.

Release Please is excluded from the agent-branch immutability ruleset because it regenerates its
canonical release branch as release state changes. That exclusion is exact to the Release Please
branch; it is not a general automation bypass.


## Changelog and release notes

JameFirewall uses **Towncrier 26.9.0** as the sole renderer of `CHANGELOG.md`. The public changelog
follows **Keep a Changelog 1.1.0** and Semantic Versioning. Release Please remains responsible for
version proposals, tags, and GitHub Releases, but it is configured with `skip-changelog: true` and
must not write or style `CHANGELOG.md`.

Every ordinary pull request supplies exactly the change evidence Towncrier expects in
`changelog.d/`. Public fragments use one of the Keep a Changelog categories:

- `added`
- `changed`
- `deprecated`
- `removed`
- `fixed`
- `security`

Changes with no user-visible release-note impact still add an `internal` fragment. The repository
Towncrier template deliberately excludes the `internal` category from generated public release
notes. This preserves a mandatory per-PR changelog decision without publishing CI, governance, or
test-maintenance noise.

Fragments should describe observable product impact in plain English. They must not contain
decorative emoji, generated marketing copy, commit-log narration, or implementation-only details.
Use `towncrier create` when practical; orphan fragments beginning with `+` are valid when no
tracked issue exists.

A release is prepared in a dedicated pull request before the Release Please version PR is merged.
That pull request uses branch `release/changelog-X.Y.Z` and title
`chore(release): prepare changelog X.Y.Z`. The `release` scope exists only for this governed
release-preparation lifecycle.

Ordinary pull requests are not allowed to edit `CHANGELOG.md` directly. A release-preparation PR
is the only recurring writer: it runs Towncrier against the proposed version, consumes all pending
fragments, and commits only the resulting `CHANGELOG.md` plus fragment deletions. CI rejects a
release-preparation PR that also changes source, configuration, the Towncrier template, or adds new
fragments.

The standard commands are:

```bash
git switch -c release/changelog-X.Y.Z
uv run towncrier build --yes --version X.Y.Z --date YYYY-MM-DD
uv run python scripts/validate_release_changelog.py --version X.Y.Z --require-clean-fragments
```

The subsequent Release Please PR is accepted only when its proposed version already has one
validated changelog entry and no pending fragments remain. Release Please does not get an exception
to generate or rewrite release notes.

The generated public categories are ordered exactly as Keep a Changelog defines them:

```text
Added
Changed
Deprecated
Removed
Fixed
Security
```

Do not hand-edit generated release sections to change their style. Correct the originating
Towncrier fragments or configuration and regenerate the release entry instead.

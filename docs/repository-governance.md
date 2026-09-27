# Repository governance

JameFirewall treats GitHub repository settings as the authoritative merge boundary. Checked-in
workflows and this document define the expected profile, but they do not replace an active GitHub
ruleset.

## Public-repository profile

The repository is intended to use the GitHub Free public-repository ruleset feature so that
`main` cannot be updated directly.

Expected repository merge settings:

- Allow auto-merge: enabled.
- Merge commits: disabled.
- Squash merging: disabled.
- Rebase merging: enabled.
- Automatically delete head branches: optional and recommended.

## `main` ruleset

Create one active branch ruleset targeting the default branch with no bypass actors.

Required protections:

- Require a pull request before merging.
- Preserve `.github/CODEOWNERS` as the explicit ownership map for critical surfaces.
- Do not require Code Owner approval while the repository has a single maintainer whose GitHub
  identity is also the author identity used by repository agents; GitHub forbids self-approval and
  that configuration would deadlock native auto-merge rather than add an independent reviewer.
- Keep GitHub's extra approval protection for unattributed Copilot pull requests enabled. This is
  separate from Code Owner review and does not apply to the current agent PRs attributed to
  `@roymejia2217`.
- Keep the server-canonical `required_reviewers` collection explicitly empty until an independent
  reviewing team is introduced.
- Dismiss stale approvals when new commits affect governed paths.
- Require status checks before merging.
- Require branches to be up to date before merging.
- Required check: `PR Governance`.
- Required check: `Required CI`.
- Require conversation resolution before merging.
- Require linear history.
- Block force pushes.
- Restrict deletions.

The required checks are intentionally aggregate job names. Internal job decomposition may evolve
without weakening the repository-level merge contract.

## Published agent branch ruleset

A second active branch ruleset, `agent-branch-immutability`, targets every branch except the
default branch and the exact Release Please branch. It has no bypass actors and contains only the
`non_fast_forward` rule.

This deliberately does not restrict branch deletion: merged topic branches must remain eligible for
GitHub's automatic head-branch cleanup. It also does not require linear history on topic branches,
because GitHub's native Update branch operation may merge the current base into a pull-request
branch without rewriting already published commits.

Commit governance distinguishes that synchronization merge structurally rather than by message.
The merge must have exactly two parents, the base-side parent must belong to current protected-base
history, and the stored tree must equal Git's own automatic merge tree. Normal commits continue
through the pinned Commitlint profile.

The Release Please branch is the only branch excluded by exact name because Release Please
regenerates that automation-owned branch as release state changes. The exclusion does not apply to
other agent or human branches.

## Pull request metadata policy

JameFirewall does not treat its PR-body shape as a universal industry specification. No such
specification exists. The policy is a narrow repository contract derived from documented external
practice:

- Conventional Commits defines machine-readable title and commit semantics.
- Google Engineering Practices defines the information a durable change description should carry:
  what changed, why it changed, and relevant context.
- GitHub provides the native pull-request-template mechanism and recommends capturing purpose,
  related issues, and testing notes.
- GitHub required status checks and rulesets are the actual merge-enforcement boundary.

The body contract is therefore limited to `What`, `Why`, `Testing`, and `Related issues` for
human and agent pull requests. It deliberately excludes decorative emoji, numbered headings,
self-attested quality checklists, manual release-type fields, and mandatory architecture/TDD
prose. Those items either have no general standard or duplicate evidence already produced by CI
and release tooling.

Release Please is a typed exception because its generated pull-request body is parsed again during
release creation. That body remains tool-owned and is validated with the same upstream
`release-please` 17.3.0 parser resolved by the pinned Release Please action. The exception is
identity-, repository-, and branch-bound; the human PR-body validator is not weakened.

The semantic-release job follows the permission profile documented by the pinned Release Please
action: `contents: write`, `issues: write`, and `pull-requests: write`. Those permissions are
scoped to that job. Release Please is also configured with `force-tag-creation: true`, so the
release tag is created explicitly before GitHub Release creation. This keeps tag authority inside
the pinned upstream release engine while avoiding any operator-created recovery tag or broader
workflow-write credential. The downstream verified-asset publisher remains limited to
`contents: write` so release orchestration authority is not inherited by artifact publication.

The in-repository validator is an enforcement adapter for this documented policy, not an
independent source of engineering policy. `PR Governance`, once required by the host ruleset,
fails closed when the description contract is not satisfied.

## Agent-only merge eligibility

`PR Governance` runs from the trusted base revision through `pull_request_target`. It never
checks out pull-request head content. The workflow rejects pull requests whose head repository is
not the JameFirewall repository itself.

That policy means public forks may inspect and fork the source, but only branches created by actors
with push access to this repository are candidates for the automated merge path.

Governance-critical paths remain covered by `.github/CODEOWNERS` so ownership is explicit and
future multi-maintainer review policy has a canonical source. While `@roymejia2217` is the sole
maintainer and repository agents commit through that same GitHub identity, CODEOWNER review is not
a merge requirement because it cannot provide an independent approval. Critical changes remain
fail-closed behind the same trusted-base `PR Governance` and `Required CI` checks as every other
merge candidate. If an independent maintainer is added, required CODEOWNER review can be enabled
without changing the ownership map.

## Required CI

`Required CI` is fail-closed and joins Linux quality with the native Windows runtime lane. The
Windows lane includes:

- real Tk control contracts;
- a real Windows Defender Firewall adapter round trip;
- a pinned 7-Zip system E2E through settings, activation, rule inspection, and deactivation;
- a production PyInstaller build;
- a Pester black-box launch of the packaged executable.

A successful package build by itself is never sufficient evidence for merge.

## Current host state

The visibility/bootstrap migration is complete. The repository is public, repository-native
auto-merge is enabled, and `main-protection` is the sole default-branch ruleset. Its live GitHub
representation is required to match the checked-in JSON contract exactly before governance changes
are promoted.

The temporary `main-bootstrap-protection` ruleset has been retired. It must not be recreated as
part of ordinary development. Future repository-policy changes use the same branch → pull request
→ required checks → exact-head rebase-merge lifecycle as product changes.

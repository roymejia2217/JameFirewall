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

The body contract is therefore limited to `What`, `Why`, `Testing`, and `Related issues`.
It deliberately excludes decorative emoji, numbered headings, self-attested quality checklists,
manual release-type fields, and mandatory architecture/TDD prose. Those items either have no
general standard or duplicate evidence already produced by CI and release tooling.

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

## Visibility transition

Repository visibility must be changed before applying the intended GitHub Free public-repository
ruleset profile. Apply and verify the protections immediately after the visibility transition and
before any subsequent unprotected merge.

Making the repository public exposes source history, Actions history, and Actions logs. The
repository remains proprietary unless its license is changed separately; public visibility does not
grant an open-source license by itself.


## Bootstrap sequence for the current governance PR

The final ruleset cannot require `PR Governance` until that check exists on the default branch and
has reported successfully in the repository. GitHub requires a required status check to have run
successfully in the repository recently before it can be selected as a required check.

Use this one-time bootstrap sequence:

1. Change repository visibility from private to public.
2. Create a temporary active rule for the default branch that requires pull requests, linear
   history, conversation resolution, strict `Required CI`, and blocks force pushes and deletion.
3. Merge the bootstrap governance PR by rebase only after its latest `Required CI` is successful.
4. Open one ordinary same-repository agent PR so the trusted-base `PR Governance` workflow runs
   from `main`.
5. After `PR Governance` and `Required CI` both report success, import
   `.github/rulesets/main-protection.json` and activate it. Keep CODEOWNERS review disabled until
   an independent maintainer exists.
6. Enable repository-native auto-merge. Agent PRs may then opt into native auto-merge; GitHub will
   complete the rebase only when every active requirement is satisfied.

Do not require `PR Governance` during step 2: the workflow does not yet exist on the trusted base
revision, so doing so would deadlock the bootstrap PR.

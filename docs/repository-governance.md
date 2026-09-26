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
- Require review from Code Owners for paths covered by `.github/CODEOWNERS`.
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

## Agent-only merge eligibility

`PR Governance` runs from the trusted base revision through `pull_request_target`. It never
checks out pull-request head content. The workflow rejects pull requests whose head repository is
not the JameFirewall repository itself.

That policy means public forks may inspect and fork the source, but only branches created by actors
with push access to this repository are candidates for the automated merge path.

Governance-critical paths are additionally covered by `.github/CODEOWNERS`. Changes to workflows,
dependency policy, PyInstaller packaging, native Windows acceptance tests, or the governance
contracts require approval from `@roymejia2217`. Ordinary product-code PRs do not acquire this
manual-review requirement solely from CODEOWNERS and remain eligible for native auto-merge after
their required checks pass.

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

Repository visibility must be changed before configuring the public-repository ruleset. GitHub
disables push rulesets when a repository changes from private to public, so protections are applied
after the visibility transition and verified before any pull request is merged.

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
3. Merge the current governance PR by rebase only after its latest `Required CI` is successful.
4. Enable required CODEOWNERS review immediately after `.github/CODEOWNERS` reaches `main`.
5. Open one ordinary same-repository agent PR so the trusted-base `PR Governance` workflow runs
   from `main`.
6. After `PR Governance` and `Required CI` both report success, import
   `.github/rulesets/main-protection.json` and activate it.
7. Enable repository-native auto-merge. Agent PRs may then opt into native auto-merge; GitHub will
   complete the rebase only when every active requirement is satisfied.

Do not require `PR Governance` during step 2: the workflow does not yet exist on the trusted base
revision, so doing so would deadlock the bootstrap PR.

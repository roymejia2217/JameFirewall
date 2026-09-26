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

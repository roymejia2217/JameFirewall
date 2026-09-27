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

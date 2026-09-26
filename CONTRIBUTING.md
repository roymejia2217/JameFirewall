# Contributing to JameFirewall

JameFirewall treats contribution metadata as part of the engineering record, but it does not invent
a private formatting system where an established convention already exists.

## Pull request title

Pull request titles and commit messages follow **Conventional Commits 1.0.0**. The repository
validates pull request titles with `amannn/action-semantic-pull-request` and validates commit
history separately. The allowed types and scopes are intentionally repository-specific extensions
of that published convention.

Reference: https://www.conventionalcommits.org/en/v1.0.0/

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

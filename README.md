# JameFirewall

Windows desktop application for managing application-specific Windows Defender Firewall rules.

JameFirewall scans configured software directories, identifies executable files,
and creates or removes Windows Defender Firewall rules for those applications.
Blocking is applied to both inbound and outbound traffic. The application also
audits its managed rules and can discover installed software paths from the
Windows Registry.

The repository and desktop application use the `JameFirewall` name. Python
project metadata uses the normalized distribution name `jame-firewall`.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Architecture](#architecture)
- [Development](#development)
- [Releases](#releases)
- [Contributing](#contributing)
- [License](#license)

## Install

JameFirewall targets Windows and requires Python 3.11 or later when it is run
from source. Clone the repository and synchronize the locked environment with
[uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/roymejia2217/JameFirewall.git
cd JameFirewall
uv sync --frozen --python 3.11
```

Prebuilt Windows executables are available from
[GitHub Releases](https://github.com/roymejia2217/JameFirewall/releases).

### Requirements

Firewall mutations require Windows administrator privileges. JameFirewall
requests elevation through UAC when necessary and uses native Windows firewall
interfaces for rule management.

## Usage

Launch the application from the synchronized source environment:

```sh
uv run jame-firewall
```

Use the desktop interface to configure software directories, discover installed
paths, inspect the current managed-rule state, block detected executables, or
remove rules previously created by JameFirewall. Blocking creates both inbound
and outbound rules for each selected executable.

Only one JameFirewall instance can operate on a Windows computer, across user
sessions and installations. A second launch shows a notice without loading
configuration or opening another control window. Administrator elevation happens
before exclusive ownership is acquired; declining elevation ends startup.
Ownership is retained until operation workers finish closing. After an unexpected
termination, reopening performs the usual audit of the actual firewall policy.

Managed rules use a stable native identity for each normalized Windows program path
and traffic direction, plus a dedicated `JameFirewall.v1` group. Repeating a block
operation repairs incomplete or disabled managed rules. The result is checked
against the observed firewall inventory after the operation.

The status describes configured blocking for executables discovered in the current
search directories. Complete blocking requires both enabled block rules, all firewall
profiles enabled, local rules allowed, and matching rules in the active policy store.
Partial coverage, policy restrictions, and query errors are displayed separately.
This is a policy inspection; it does not perform a live network traffic test or
certify coverage of files the directory scanner cannot discover.

Rules from older versions (`<program> jame-block` or `<program> adobe-block`) are
reported as pending review and retained when deactivating. Their display names do
not establish ownership. Review their program paths and remove them explicitly in
Windows Defender Firewall if they are no longer wanted; do not delete other rules
based solely on matching text. Deactivation removes only verified rules in the new
managed namespace and reports individual rules rather than unique display names.

Operations run one at a time; activation, deactivation, refresh, and configuration
remain unavailable until the current operation and its visual updates complete.
Closing the window stops further commands and scanning, waits responsively for the
command already in progress, and then releases the worker. Each command has a
maximum configured timeout of 30 seconds. Operating-system process creation and a
blocked filesystem call can delay shutdown beyond that deadline.

Cancellation does not undo firewall changes already applied. Reopen the application
to audit the resulting state and repair incomplete coverage. The activity log keeps
a bounded recent history; older or excessive messages may be omitted.

## Architecture

JameFirewall follows a Ports and Adapters architecture with explicit separation
between domain logic, operating-system integration, persistence, and the
Windows desktop presentation layer.

- `src/jame_firewall/core/` contains entities, ports, and application use cases.
- `src/jame_firewall/infrastructure/` implements Windows Firewall, Registry,
  filesystem, process, UAC, and persistence adapters.
- `src/jame_firewall/presentation/` contains the Tkinter/ttkbootstrap desktop
  interface and thread-safe UI dispatching.
- `src/jame_firewall/infrastructure/container.py` is the production composition
  root that wires ports to adapters.

## Development

Install the locked development environment and run the repository quality
checks with the same commands used by CI:

```sh
uv sync --frozen --all-extras --python 3.11
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run mypy src tests scripts
uv run pytest -m "not windows_only"
```

The repository also enforces Conventional Commits, governed pull-request
metadata, Towncrier changelog evidence, native Windows acceptance tests, and
packaged-runtime verification. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
changing code or repository policy.

## Releases

Release Please owns version proposals, tags, and GitHub Releases. Verified
Windows executables are published only after the repository release workflow
completes its native Windows preflight and artifact validation.

See [GitHub Releases](https://github.com/roymejia2217/JameFirewall/releases)
for published versions.

## Contributing

Pull requests must follow the governed contribution process documented in
[CONTRIBUTING.md](CONTRIBUTING.md). Repository rulesets and the required
`PR Governance` and `Required CI` checks are the merge authority.

Use [GitHub Issues](https://github.com/roymejia2217/JameFirewall/issues) for
defect reports and project questions.

## License

JameFirewall is licensed under the GNU General Public License version 3 or any
later version (`GPL-3.0-or-later`).

Copyright © 2026 Roy Mejía. See [LICENSE](LICENSE).

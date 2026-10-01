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

Settings edits, including automatic discovery, remain a draft until **Save**.
Saving replaces the complete list once; a failed save keeps the previous settings
and leaves the dialog open for retry. **Cancel** discards the draft. An empty
directory list is preserved as an intentional setting.

On Windows, production configuration is shared at the system's ProgramData known
folder under `JameFirewall/jamefirewall_config.json`, normally
`C:\ProgramData\JameFirewall\jamefirewall_config.json`. Windows resolves this
location independently of the process's `ProgramData` environment variable.
The folder and file have protected permissions for administrators and SYSTEM.
Unexpected ownership, permissions, or storage links prevent startup.

On first use, an existing `jamefirewall_config.json` beside the executable (or in
the source tree when running from source) is validated and copied into protected
storage. The original is retained. Once protected configuration exists, it takes
precedence over the legacy copy, even if the protected copy is invalid.
Configuration accepts only a `directories` array of absolute paths, with at most
256 entries, 32,767 characters per path, and a 1 MiB UTF-8 JSON file. Supported root
variables are `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, `USERPROFILE`,
`APPDATA`, and `LOCALAPPDATA`; they expand for the elevated process's environment.

Invalid or unreadable configuration shows a startup error and preserves the
file. Correct it as an administrator, or move it aside to restore from the valid
legacy copy or defaults. Verify unexpected permissions before replacing storage.
Saving flushes a temporary file in the same folder before replacing the current
file. This preserves the previous file on failures before replacement; it does
not guarantee recovery from storage-device failure or power loss. A terminated
process can leave a `.jamefirewall-*.tmp` file that is never loaded as configuration.

Managed rules use a stable native identity for each normalized Windows program path
and traffic direction, plus a dedicated `JameFirewall.v1` group. Repeating a block
operation repairs incomplete or disabled managed rules. The result is checked
against the observed firewall inventory after the operation.
Inventory queries select the managed group, requested native identity prefixes and legacy
name suffixes in the provider. They retain at most 2,048 candidate rules and consume at
most 8,192 query rows, including overlaps between selectors. The scope accepts up to
eight lowercase namespaces of at most 64 letters, digits or hyphens each. Duplicate or
changing native identities, provider errors and exceeded limits produce an error rather
than a truncated success. Activation checks the projected candidate count before creating
rules. Rule selection is read-only; ownership still requires the exact identity, path,
direction and application group. Legacy and foreign rules remain visible and retained.
These limits bound results handled by the command, not the Windows provider's internal
caches or work. Per-command and operation deadlines remain in force.

The status describes configured blocking for executables discovered in the current
search directories. Complete blocking requires both enabled block rules, all firewall
profiles enabled, local rules allowed, and matching rules in the active policy store.
Partial coverage, policy restrictions, and query errors are displayed separately.
This is a policy inspection; it does not perform a live network traffic test or
certify coverage of files the directory scanner cannot discover.

Scanning streams local directory entries and reports missing or inaccessible roots,
nonregular executable files, links, junctions and other reparse points as incomplete
scope. Network roots (UNC or mapped remote drives) are not accepted. Directory paths
retain their lexical identity when saved so links remain visible to validation.
An incomplete scan always produces a partial status and activation creates no rules;
correct the reported roots or omissions before retrying. Existing rules are preserved.
An explicitly empty directory list remains a complete empty scope.

Each scan allows at most 256 roots, 10,000 folders, 200,000 entries, 10,000 executables,
100 reported issues and 60 seconds. Queued directory paths and retained executable
paths/keys share a budget of 2,000,000 characters; issue paths are truncated to 512
characters. These are traversal and retained-data limits, not a byte-exact process
memory guarantee. Cancellation and deadlines are checked between filesystem calls;
a blocked OS call can exceed the deadline. Reparse checks do not provide an atomic
security boundary against another process replacing directories during enumeration.
Use stable, trusted local software folders for the elevated application.

Rules from older versions (`<program> jame-block` or `<program> adobe-block`) are
reported as pending review and retained when deactivating. Their display names do
not establish ownership. Review their program paths and remove them explicitly in
Windows Defender Firewall if they are no longer wanted; do not delete other rules
based solely on matching text. Deactivation removes only verified rules in the new
managed namespace and reports individual rules rather than unique display names.

Only one JameFirewall instance can operate on a Windows computer, across user
sessions and installations. A second launch shows a notice without loading
configuration or opening another control window. Administrator elevation happens
before exclusive ownership is acquired; declining elevation ends startup.
Ownership is retained until operation workers finish closing. After an unexpected
termination, reopening performs the usual audit of the actual firewall policy.

Autodetection runs on the shared operation worker while Settings remains responsive.
Its directory edits stay in the draft until Save. Cancel discards the draft and ignores
late results; an admitted discovery still holds the operation slot until it finishes.
Discovery checks shutdown cancellation, allows at most 4,096 registry subkeys and 256
found paths, and has a cooperative 30-second deadline. Errors retain the draft.

Operations run one at a time; activation, deactivation, refresh, and configuration
remain unavailable until the current operation and its visual updates complete.
Activation, deactivation and audit share a cooperative 120-second operation budget,
including the audit following a mutation. Nested steps never reset that deadline.
Each command has a maximum timeout of 30 seconds, shortened to the operation time
remaining. Commands retain at most 8 MiB of combined raw stdout/stderr; overflow is
an explicit failure, and partial output is never accepted as a valid firewall inventory.
Firewall mutations run sequentially in batches of at most eight rules, with an 8,000-byte
quoted JSON payload limit measured in UTF-16. Each batch reads the local inventory once
and re-fetches existing native identities before validating their group, program and
direction. A failed rule does not authorize touching a foreign rule. Known failures are
checked against the final inventory; an incomplete command or malformed result aborts
later batches and requires refreshing the actual state. Applied changes are not rolled back.

On Windows, a command starts suspended, is assigned to a private Job Object, and
resumes only after containment succeeds. Only its standard I/O handles are inherited.
The Job does not permit ordinary child-process breakaway. Timeout, output overflow,
cancellation and normal parent exit reclaim contained descendants, including children
holding output pipes open. Cleanup polls for completion for at most five seconds and
reports failures explicitly. This contains ordinary subprocess descendants; a process
started through an external broker such as WMI is outside that Job's ownership.

Closing the window stops further commands and scanning, requests cancellation of the
active command tree, and waits responsively for worker cleanup before releasing
instance ownership. Operating-system process creation, cleanup APIs and a blocked
filesystem call are not interruptible Python calls and can delay shutdown beyond
cooperative deadlines. A deadline or command failure aborts additional mutations;
the interface reports an error rather than claiming a successful or protected state.

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

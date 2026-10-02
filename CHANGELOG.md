# Changelog

All notable changes to JameFirewall are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Unreleased changes are recorded as Towncrier fragments in [`changelog.d/`](changelog.d/).

## [Unreleased]

<!-- towncrier release notes start -->

## [0.3.1](https://github.com/roymejia2217/JameFirewall/releases/tag/v0.3.1) - 2026-10-02

### Fixed

- Exercise scanner and native firewall inventory capacity profiles in Windows CI with real
  workloads,
  correctness assertions, and measured duration and process working-set data.
  ([#35](https://github.com/roymejia2217/JameFirewall/issues/35))
- Remove fixed firewall rule-count ceilings and reconcile mutations by exact rule identity in
  payload-sized batches to reduce Windows Firewall operation time under larger workloads.
  ([#39](https://github.com/roymejia2217/JameFirewall/issues/39))


## [0.3.0](https://github.com/roymejia2217/JameFirewall/releases/tag/v0.3.0) - 2026-10-01

### Changed

- License JameFirewall under GNU GPL version 3 or any later version.

### Fixed

- Identify firewall rules by executable path and direction, repair incomplete managed blocks, and
  report partial coverage and query failures accurately. Retain older rules for explicit review
  instead of deleting rules by matching display names. Process firewall changes in bounded
  sequential batches to reduce repeated command launches while preserving ownership checks,
  partial-failure reporting and final verification of effective coverage. Select and bound firewall
  inventory candidates while preserving legacy and foreign-rule visibility, rejecting incomplete
  reads and preventing activation from exceeding auditable capacity.
- Prevent multiple JameFirewall instances from modifying firewall rules or configuration on the same
  Windows computer. Show a notice for duplicate launches, retain exclusive ownership through worker
  shutdown, and allow reopening after an unexpected termination.

  Preserve complete configuration on failed saves, retain unsaved edits for retry, and discard
  drafts on Cancel. Report invalid configuration instead of silently using defaults.

  Migrate validated existing settings to protected shared Windows storage without deleting the
  original. Refuse unexpected storage permissions and preserve invalid settings for diagnosis.

  Report incomplete executable scans and refuse activation without changing existing rules. Bound
  local traversal, omit links and reparse points explicitly, and keep directory autodetection
  responsive without publishing canceled drafts.

  Bound command output and total firewall operation time. Reclaim contained Windows subprocesses on
  completion, cancellation or failure, and report uncertain outcomes without continuing mutations or
  claiming protection.
- Prevent overlapping firewall operations and configuration changes, stop further work on close, and
  wait responsively for the running command before exiting. Keep activity logs bounded and use the
  system Windows PowerShell executable and modules.


## [0.2.0](https://github.com/roymejia2217/JameFirewall/releases/tag/v0.2.0) - 2026-09-27

### Added

- Added the canonical multi-resolution JameFirewall application icon for Windows.

### Changed

- Hardened native Windows acceptance and packaged-runtime validation before release publication.
- Improved Windows Firewall rule discovery by filtering managed rules at the NetSecurity provider.

### Fixed

- Fixed packaged `ttkbootstrap` runtime asset collection in the Windows executable.
- Fixed successful empty PowerShell firewall queries being treated as command failures.
- Stabilized Windows Firewall acceptance by querying the exact managed rules created for the
  installed application fixture.

## [0.1.0](https://github.com/roymejia2217/JameFirewall/releases/tag/v0.1.0) - 2026-09-25

### Added

- Added the initial Windows desktop application for managing Windows Defender Firewall block rules.
- Added executable discovery, inbound and outbound rule management, status auditing, and settings.
- Added the initial packaged Windows executable release workflow.

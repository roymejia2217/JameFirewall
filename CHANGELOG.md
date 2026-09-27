# Changelog

All notable changes to JameFirewall are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Unreleased changes are recorded as Towncrier fragments in [`changelog.d/`](changelog.d/).

## [Unreleased]

<!-- towncrier release notes start -->

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

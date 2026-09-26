# JameFirewall CI testing contract

JameFirewall uses layered, tool-backed verification. No single custom script is treated as proof
that a Windows desktop release works.

## Authoritative tooling

- **pytest**: Python unit, contract, integration, native-Windows, and host-level system tests.
- **PyInstaller**: produces the same one-file Windows executable delivered to users.
- **Pester**: validates the packaged executable as a black-box Windows process.
- **Windows Defender Firewall tooling**: native tests exercise the real `netsh`,
  `Get-NetFirewallRule`, and `Get-NetFirewallApplicationFilter` surfaces.
- **Chocolatey**: installs the pinned 7-Zip system fixture on the GitHub-hosted Windows runner.
- **GitHub Actions**: executes Linux and Windows lanes independently and joins them through one
  required aggregate job.

The CI workflow pins third-party GitHub Actions to immutable commit SHAs and uses
`uv sync --frozen` for the Python environment.

## Verification layers

1. Linux quality verifies Ruff, formatting, mypy strict mode, and the portable pytest suite.
2. Windows native pytest builds the real Tk widget tree and invokes its command bindings.
3. Windows firewall integration performs a real create/audit/delete rule round trip using an
   isolated rule suffix and mandatory cleanup.
4. The Windows system E2E installs pinned 7-Zip 26.3.0, opens JameFirewall settings, adds
   `C:\Program Files\7-Zip` through the real Tk button path, saves the configuration, invokes
   the real activation control, and verifies that every discovered 7-Zip executable receives
   enabled inbound and outbound `Block` rules in Windows Defender Firewall.
5. The same E2E invokes the real deactivation control and fails unless those rules are removed.
6. PyInstaller builds the production executable on the native Windows runner.
7. Pester copies that executable outside the repository, removes project Python from `PATH`,
   launches it, requires a real `JameFirewall` top-level window, and rejects startup crash logs.
8. The aggregate `Required CI` job fails unless both Linux and Windows lanes succeed.

## System fixture policy

7-Zip is used because it is small, deterministic, has executable files under the standard
`Program Files` hierarchy, and does not require proprietary application licensing. CI installs
version 26.3.0 explicitly rather than depending on whichever 7-Zip version happens to be baked
into the runner image.

The test does not assert only that a command returned zero. It reads the actual Windows Firewall
state and validates program path, direction, action, and enabled state for the rules produced by
JameFirewall.

## UI automation boundary

Tk/ttk does not expose its widget tree through Microsoft UI Automation in the same way as WPF,
WinForms, WinUI, or Qt. A UIA driver is therefore not accepted as proof of semantic button
accessibility for this application.

The Windows system E2E drives the real Tk widgets inside the application process and replaces only
the operating-system directory picker response with the deterministic 7-Zip path. The directory
picker itself is outside JameFirewall's business boundary. All configuration persistence,
activation/deactivation callbacks, asynchronous dispatch, directory scanning, firewall adapters,
and Windows Firewall state remain real.

The packaged executable is independently validated as a black box by Pester. If the presentation
layer later migrates to a UIA-accessible toolkit, a semantic UIA end-to-end lane should be added
instead of coordinate- or image-based automation.

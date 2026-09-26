# JameFirewall CI testing contract

JameFirewall uses layered, tool-backed verification. No single custom script is treated as proof
that a Windows desktop release works.

## Authoritative tooling

- **pytest**: Python unit, contract, integration, and native-Windows tests.
- **PyInstaller**: produces the same one-file Windows executable delivered to users.
- **Pester**: validates the packaged executable as a black-box Windows process.
- **Windows Defender Firewall tooling**: the native integration lane exercises the real `netsh` and
  PowerShell firewall adapters on an ephemeral GitHub-hosted Windows runner.
- **GitHub Actions**: executes Linux and Windows lanes independently and joins them through one
  required aggregate job.

The CI workflow pins third-party GitHub Actions to immutable commit SHAs.

## Verification layers

1. Linux quality verifies Ruff, formatting, mypy strict mode, and the portable pytest suite.
2. Windows native pytest builds the real Tk widget tree and invokes its command bindings.
3. Windows firewall integration performs a real create/audit/delete rule round trip using an
   isolated rule suffix and mandatory cleanup.
4. PyInstaller builds the production executable on `windows-latest`.
5. Pester copies that executable outside the repository, removes project Python from `PATH`,
   launches it, requires a real `JameFirewall` top-level window, and rejects startup crash logs.
6. The aggregate `Required CI` job fails unless both Linux and Windows lanes succeed.

## UI automation boundary

Tk/ttk does not expose its widget tree through Microsoft UI Automation in the same way as WPF,
WinForms, WinUI, or Qt. Therefore UIA drivers are not accepted as proof of button accessibility for
this application: they would provide false confidence. The Tk controls are exercised directly by
pytest on native Windows, while the packaged executable is independently validated as a black box
by Pester.

If the presentation layer later migrates to a UIA-accessible toolkit, a semantic UIA end-to-end
lane should be added rather than coordinate- or image-based automation.

# JameFirewall CI testing contract

JameFirewall uses layered, tool-backed verification. No custom script or successful build is
accepted by itself as proof that the Windows desktop application works.

## Authoritative tooling

- **pytest** executes Python unit, contract, native-Windows, and system-acceptance tests.
- **pytest-benchmark 5.3.0** records controlled Windows scan and inventory timings as JSON. The
  benchmark setup is outside the measured scan; timing remains diagnostic until repeated hosted
  runner data supports a stable regression threshold.
- **psutil 7.2.2** records the Windows test process working set around measured workloads.
- **Actionlint 1.7.12** validates GitHub Actions workflow semantics from its official repository,
  pinned to immutable commit `914e7df21a07ef503a81201c76d2b11c789d3fca`.
- **PyInstaller** produces the same one-file Windows executable delivered to users.
- **Pester 5.7.1** validates the packaged executable as a black-box Windows process.
- **Chocolatey + 7-Zip 26.3.0** provides a pinned real installed Windows application fixture.
- **Windows NetSecurity / Windows Defender Firewall** provides the native firewall state inspected
  by the system acceptance lane.
- **GitHub Actions** executes independent Linux, Windows-system, and Windows-package lanes and
  combines them through the stable `Required CI` check.

Third-party GitHub Actions are pinned to immutable commit SHAs. The uv executable is also pinned
explicitly to `0.12.19`; CI does not resolve an unbounded latest uv release at runtime.

## Pull-request acceptance layers

1. **Linux Quality** validates the PR description contract, every PR commit message, Actionlint,
   Ruff, Ruff formatting, mypy strict mode, and the portable pytest suite.
2. **Windows System Acceptance** runs on the explicit `windows-2025` hosted image. It first builds
   the real Tk/ttk widget tree and invokes the primary application control bindings. Native
   storage contracts verify administrator/SYSTEM permissions, reject untrusted existing storage,
   and preserve the previous configuration when Windows denies replacement or a writer is
   terminated before publishing its flushed temporary file. Native scanner contracts use
   real junctions, cycles and denied directory-list permissions, enforce finite traversal
   budgets and cancellation, and require incomplete scope to remain visible. Scanner load profiles
   traverse 1,000, 10,000 and 200,000 real NTFS entries, including 100, 1,000 and 5,000 `.exe`
   paths respectively. These zero-byte files measure the scanner's path-discovery work; the pinned
   7-Zip fixture continues to cover real executable paths through the firewall flow. Tests assert
   complete results, exact counts, uniqueness and configured bounds while recording benchmark
   JSON, fixture setup duration and process working set. The Settings
   contract verifies that discovery leaves the Tk event loop responsive and that Cancel
   suppresses a worker's late result. Native process contracts require timeout, output
   overflow, cancellation and successful-parent completion to stop pipe-owning descendants.
   Repeated runs check handle and thread retention. Native firewall batch contracts create
   ten executable targets spanning three mutation batches, verify effective protection,
   repeated activation without duplicates and complete deactivation. A separate collision
   fixture requires a foreign rule to survive while adjacent owned operations succeed.
   JUnit suite properties record the serial 40-process mutation baseline, the six-process
   batch equivalent and elapsed times. Serial timing covers mutations only; batch full-cycle
   timing also includes scans, inventories, repeated activation and follow-up audits. Timing
   is diagnostic; command counts and observed policy are deterministic assertions.
   Scoped inventory contracts add 128 real unrelated rules and verify that owned rules,
   a case-insensitive legacy display suffix and a foreign native-name collision remain
   distinguishable. An additional native inventory load case verifies 128 owned rules across 64
   executable paths and records its measured duration and process working set. These cases preserve
   foreign/legacy rules on deactivation and require an
   authoritative empty inventory after fixture cleanup. Native PowerShell fault fixtures
   reject candidate/row quotas, duplicate or changing identities, denied access and false
   absence errors before expensive filter reads. JUnit properties record full catalog row
   counts versus scoped candidate counts. Full-catalog enumeration and scoped verification
   timings cover different work and are diagnostic, not a speed ratio or timing gate.
3. The same system lane installs 7-Zip 26.3.0 into `C:\Program Files\7-Zip`, verifies the
   installed product version, opens JameFirewall Settings, adds that directory through the real
   Add control, verifies Cancel discards edits, injects a replacement failure through the real
   Save control, and requires the modal, disk and saved memory to retain their previous state.
   Retrying Save must commit the full draft and reload it from disk before activation.
4. Before successful activation, a missing configured root must produce partial status
   and an incomplete-scan diagnostic without creating product firewall rules. After correcting
   the scope, it invokes the real Activate control and requires every executable discovered from the 7-Zip
   directory to have enabled Windows Defender Firewall **Inbound** and **Outbound** rules with
   action **Block**.
5. An independent ActiveStore probe checks native identities, the application group,
   profiles, enforcement and exact executable paths. Repeating Activate must retain exactly
   two rules per executable without duplicates. Deactivate must remove the managed namespace
   and restore the unprotected status.
6. **Windows Packaged Runtime** independently builds `dist/JameFirewall.exe` with PyInstaller.
   This job does not depend on the 7-Zip lane, so a system-test failure cannot hide packaging
   evidence and a packaging failure cannot hide system behavior evidence.
7. Pester copies the executable outside the repository, removes project Python from `PATH`,
   migrates a legacy configuration into protected ProgramData storage, and inspects its owner
   and ACL. It requires a real `JameFirewall` top-level window, rejects a duplicate launch,
   verifies both duplicate processes exit after acknowledgment, and reports corrupt persisted
   configuration through a native startup error without replacing it or opening the control UI.
   Startup crash logs fail acceptance. This fixture requires an isolated runner without an
   existing production configuration and cleans up only the storage it creates.
8. **Required CI** is fail-closed and succeeds only if Linux Quality, Windows System Acceptance,
   and Windows Packaged Runtime all succeed.

## UI automation boundary

Tk/ttk does not expose its widget tree through Microsoft UI Automation with the semantic coverage
available from WPF, WinForms, WinUI, or Qt. JameFirewall therefore does not treat a UIA driver or
coordinate/image automation as authoritative evidence for its Tk controls.

The system E2E executes the actual Tk controls in-process on native Windows while retaining the
production dependency graph: filesystem scanner, persistence adapter, UAC adapter, firewall
adapter, and Windows Defender Firewall. Only the native directory-picker response is substituted so
CI can deterministically select the pinned 7-Zip installation directory.

The packaged executable is validated separately as a black box with Pester. There is no
`--smoke-test` production bypass and no alternate test-only startup path in the released program.

## Timing and diagnostics

Windows Firewall mutation is real OS integration work. The system E2E therefore waits for bounded
observable UI completion rather than assuming an arbitrary short fixed delay. Completion predicates
normalize Tcl/ttk values before comparison and require the shared dispatcher to settle.
The UI acceptance wait uses the production 120-second operation budget plus a 10-second
cleanup/UI margin; it does not reset the product's deadline. Process commands are capped
at 30 seconds and 8 MiB combined output; expired or incomplete results cannot prove success. A timeout remains fail-closed and reports the current
application status, button states, and activity log; it is never converted to a skip or success.

## Release boundary

The release workflow repeats the quality and Windows acceptance boundary before Release Please may
create a release. The Windows release preflight produces one candidate executable, validates it with
the 7-Zip system E2E and Pester, records its SHA-256, and uploads it as an Actions artifact.

The publication job downloads that exact candidate, validates both the preflight SHA-256 and the
artifact checksum manifest, and stages canonical release names without rebuilding. Release asset
upload does not use `--clobber`; an existing conflicting asset is a failure rather than an implicit
overwrite.

Creating a release manually through `workflow_dispatch` is not an authorized release path. The
separate `release-asset-recovery.yml` workflow is an exceptional repair boundary for an already
existing release whose verified asset publication failed after release creation. It never rebuilds
the executable. It accepts only a completed failed run of the canonical release workflow on
`main`, binds that run to an exact source HEAD SHA, binds the existing release and tag to an exact
target SHA, reuses the named `windows-release-candidate` artifact, revalidates the expected SHA-256,
and refuses to replace an existing release asset.

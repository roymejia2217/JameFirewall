BeforeAll {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class JameWindowProbe {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder name, int maximum);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string kind, string title);
    public static IntPtr FindButton(IntPtr parent, IntPtr after) {
        // Keep null in C#: PowerShell converts a null string argument to an empty title.
        return FindWindowEx(parent, after, "Button", null);
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint message, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out UIntPtr result);
}
"@

    $sourceExe = $env:JAMEFIREWALL_EXE
    if ([string]::IsNullOrWhiteSpace($sourceExe)) {
        throw "JAMEFIREWALL_EXE is required."
    }

    $resolvedExe = (Resolve-Path $sourceExe).Path
    $runtimeName = "jamefirewall-runtime-" + [guid]::NewGuid().ToString("N")
    $script:runtimeDir = Join-Path ([System.IO.Path]::GetTempPath()) $runtimeName
    New-Item -ItemType Directory -Path $script:runtimeDir -Force | Out-Null

    $script:runtimeExe = Join-Path $script:runtimeDir "JameFirewall.exe"
    Copy-Item $resolvedExe $script:runtimeExe
    $script:productionDir = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) "JameFirewall"
    $script:ownsProductionDir = -not (Test-Path -LiteralPath $script:productionDir)
    if (-not $script:ownsProductionDir) {
        throw "Packaged acceptance requires an isolated runner without existing JameFirewall configuration."
    }
    $script:productionConfig = Join-Path $script:productionDir "jamefirewall_config.json"
    $script:legacyConfig = Join-Path $script:runtimeDir "jamefirewall_config.json"
    $script:legacyDirectories = @((Join-Path $script:runtimeDir "legacy-empty"))
    @{directories = $script:legacyDirectories} | ConvertTo-Json | Set-Content -LiteralPath $script:legacyConfig -Encoding utf8NoBOM
    $script:legacyContent = Get-Content -LiteralPath $script:legacyConfig -Raw

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    $script:isAdmin = $principal.IsInRole($adminRole)
}

Describe "JameFirewall packaged Windows runtime" {
    It "migrates protected config, rejects duplicates and reports corrupt config in the packaged app" {
        $script:isAdmin | Should -BeTrue

        $oldPath = $env:PATH
        $startedAfter = Get-Date
        $env:PATH = @(
            "$env:SystemRoot\System32"
            "$env:SystemRoot"
            "$env:SystemRoot\System32\Wbem"
            "$env:SystemRoot\System32\WindowsPowerShell\v1.0"
        ) -join ";"

        try {
            Start-Process -FilePath $script:runtimeExe -WorkingDirectory (Split-Path $script:runtimeExe) | Out-Null

            $windowProcess = $null
            $deadline = (Get-Date).AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 250
                $candidates = @(
                    Get-Process -Name "JameFirewall" -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.StartTime -ge $startedAfter -and
                            $_.Path -eq $script:runtimeExe
                        }
                )
                $windowProcess = $candidates |
                    Where-Object { $_.MainWindowHandle -ne 0 } |
                    Select-Object -First 1
            } while ($null -eq $windowProcess -and (Get-Date) -lt $deadline)

            $windowProcess | Should -Not -BeNullOrEmpty
            $null = $windowProcess.Handle
            $windowProcess.MainWindowHandle | Should -Not -Be 0
            $windowProcess.MainWindowTitle | Should -Be "JameFirewall"
            $windowClass = [System.Text.StringBuilder]::new(256)
            [JameWindowProbe]::GetClassName($windowProcess.MainWindowHandle, $windowClass, 256) |
                Should -BeGreaterThan 0
            $windowClass.ToString() | Should -Not -Be "#32770"
            Test-Path -LiteralPath $script:productionConfig | Should -BeTrue
            (Get-Content -LiteralPath $script:legacyConfig -Raw) | Should -Be $script:legacyContent
            $saved = Get-Content -LiteralPath $script:productionConfig -Raw | ConvertFrom-Json
            @($saved.directories).Count | Should -Be 1
            [Environment]::ExpandEnvironmentVariables($saved.directories[0]) | Should -Be $script:legacyDirectories[0]
            foreach ($path in @($script:productionDir, $script:productionConfig)) {
                $acl = Get-Acl -LiteralPath $path
                $acl.AreAccessRulesProtected | Should -BeTrue
                $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value | Should -Be "S-1-5-32-544"
                $sids = @($acl.Access | ForEach-Object {
                    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                })
                ($sids | Sort-Object) -join "," | Should -Be "S-1-5-18,S-1-5-32-544"
            }

            $secondStart = Get-Date
            $duplicateLaunch = Start-Process -FilePath $script:runtimeExe -WorkingDirectory (Split-Path $script:runtimeExe) -PassThru
            # Retain process handles before exit so Windows preserves their exit status.
            $null = $duplicateLaunch.Handle
            $duplicateProcess = $null
            $deadline = (Get-Date).AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 250
                $duplicateProcess = Get-Process -Name "JameFirewall" -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.StartTime -ge $secondStart -and
                        $_.Path -eq $script:runtimeExe -and
                        $_.MainWindowHandle -ne 0
                    } |
                    Select-Object -First 1
            } while ($null -eq $duplicateProcess -and (Get-Date) -lt $deadline)

            $duplicateProcess | Should -Not -BeNullOrEmpty
            $null = $duplicateProcess.Handle
            $duplicateProcess.MainWindowTitle | Should -Be "JameFirewall - instancia activa"
            $dialogClass = [System.Text.StringBuilder]::new(256)
            [JameWindowProbe]::GetClassName($duplicateProcess.MainWindowHandle, $dialogClass, 256) |
                Should -BeGreaterThan 0
            $dialogClass.ToString() | Should -Be "#32770"
            # Acknowledge only the duplicate notice owned by this isolated runtime fixture.
            $deadline = (Get-Date).AddSeconds(5)
            do {
                $duplicateProcess.Refresh()
                # MessageBox may use IDCANCEL for its sole OK button; IDs are not stable.
                $acceptButton = [JameWindowProbe]::FindButton(
                    $duplicateProcess.MainWindowHandle, [IntPtr]::Zero
                )
                if ($acceptButton -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 100 }
            } while ($acceptButton -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)
            $acceptButton | Should -Not -Be ([IntPtr]::Zero)
            [JameWindowProbe]::FindButton(
                $duplicateProcess.MainWindowHandle, $acceptButton
            ) | Should -Be ([IntPtr]::Zero)
            $messageResult = [UIntPtr]::Zero
            # BM_CLICK delivers the button notification expected by the native message box.
            $sent = [JameWindowProbe]::SendMessageTimeout(
                $acceptButton, 0xF5, [IntPtr]::Zero, [IntPtr]::Zero,
                2, 5000, [ref]$messageResult
            )
            $messageError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $sent | Should -Not -Be ([IntPtr]::Zero) -Because "BM_CLICK must succeed (Win32 error $messageError)"
            $duplicateProcess.WaitForExit(15000) | Should -BeTrue
            $duplicateProcess.ExitCode | Should -Be 0
            $duplicateLaunch.WaitForExit(15000) | Should -BeTrue
            $duplicateLaunch.ExitCode | Should -Be 0
            $windowProcess.Refresh()
            $windowProcess.HasExited | Should -BeFalse

            # Corrupt persisted state must show a startup error, preserve bytes and open no Tk UI.
            $windowProcess.CloseMainWindow() | Should -BeTrue
            $windowProcess.WaitForExit(45000) | Should -BeTrue
            $windowProcess.ExitCode | Should -Be 0
            [IO.File]::WriteAllText($script:productionConfig, "{")
            $errorStart = Get-Date
            $errorLaunch = Start-Process -FilePath $script:runtimeExe -WorkingDirectory $script:runtimeDir -PassThru
            $null = $errorLaunch.Handle
            $errorProcess = $null
            $deadline = (Get-Date).AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 250
                $errorProcess = Get-Process -Name "JameFirewall" -ErrorAction SilentlyContinue |
                    Where-Object { $_.StartTime -ge $errorStart -and $_.Path -eq $script:runtimeExe -and $_.MainWindowHandle -ne 0 } |
                    Select-Object -First 1
            } while ($null -eq $errorProcess -and (Get-Date) -lt $deadline)
            $errorProcess | Should -Not -BeNullOrEmpty
            $null = $errorProcess.Handle
            $errorProcess.MainWindowTitle | Should -Be "JameFirewall"
            $errorClass = [Text.StringBuilder]::new(256)
            [JameWindowProbe]::GetClassName($errorProcess.MainWindowHandle, $errorClass, 256) | Should -BeGreaterThan 0
            $errorClass.ToString() | Should -Be "#32770"
            $errorButton = [JameWindowProbe]::FindButton($errorProcess.MainWindowHandle, [IntPtr]::Zero)
            $errorButton | Should -Not -Be ([IntPtr]::Zero)
            $messageResult = [UIntPtr]::Zero
            [JameWindowProbe]::SendMessageTimeout($errorButton, 0xF5, [IntPtr]::Zero, [IntPtr]::Zero, 2, 5000, [ref]$messageResult) |
                Should -Not -Be ([IntPtr]::Zero)
            $errorProcess.WaitForExit(15000) | Should -BeTrue
            $errorLaunch.WaitForExit(15000) | Should -BeTrue
            (Get-Content -LiteralPath $script:productionConfig -Raw) | Should -Be "{"

            $crashLog = Join-Path (Split-Path $script:runtimeExe) "crash_log.txt"
            Test-Path $crashLog | Should -BeFalse
        }
        finally {
            $env:PATH = $oldPath
            $ownedProcesses = @(
                Get-Process -Name "JameFirewall" -ErrorAction SilentlyContinue |
                    Where-Object { $_.StartTime -ge $startedAfter -and $_.Path -eq $script:runtimeExe }
            )
            $ownedProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            $ownedProcesses | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue

            Remove-Item -LiteralPath $script:runtimeDir -Recurse -Force -ErrorAction SilentlyContinue
            if ($script:ownsProductionDir) {
                Remove-Item -LiteralPath $script:productionDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

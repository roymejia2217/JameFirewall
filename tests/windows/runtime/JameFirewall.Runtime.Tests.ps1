BeforeAll {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class JameWindowProbe {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder name, int maximum);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetDlgItem(IntPtr dialog, int controlId);
    private delegate bool EnumWindowCallback(IntPtr window, IntPtr parameter);
    [DllImport("user32.dll")]
    private static extern bool EnumChildWindows(IntPtr parent, EnumWindowCallback callback, IntPtr parameter);
    [DllImport("user32.dll")]
    private static extern int GetDlgCtrlID(IntPtr window);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr window, StringBuilder text, int maximum);
    public static string DescribeChildren(IntPtr parent) {
        var children = new List<string>();
        EnumChildWindows(parent, (window, parameter) => {
            var kind = new StringBuilder(256);
            var text = new StringBuilder(256);
            GetClassName(window, kind, 256);
            GetWindowText(window, text, 256);
            children.Add(String.Format("handle={0} id={1} class={2} text={3}",
                window, GetDlgCtrlID(window), kind, text));
            return true;
        }, IntPtr.Zero);
        return String.Join("; ", children);
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

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    $script:isAdmin = $principal.IsInRole($adminRole)
}

Describe "JameFirewall packaged Windows runtime" {
    It "runs one elevated instance and rejects duplicates without project Python on PATH" {
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
            $windowProcess.MainWindowHandle | Should -Not -Be 0
            $windowProcess.MainWindowTitle | Should -Be "JameFirewall"
            $windowClass = [System.Text.StringBuilder]::new(256)
            [JameWindowProbe]::GetClassName($windowProcess.MainWindowHandle, $windowClass, 256) |
                Should -BeGreaterThan 0
            $windowClass.ToString() | Should -Not -Be "#32770"

            $secondStart = Get-Date
            Start-Process -FilePath $script:runtimeExe -WorkingDirectory (Split-Path $script:runtimeExe) | Out-Null
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
            $duplicateProcess.MainWindowTitle | Should -Be "JameFirewall - instancia activa"
            $dialogClass = [System.Text.StringBuilder]::new(256)
            [JameWindowProbe]::GetClassName($duplicateProcess.MainWindowHandle, $dialogClass, 256) |
                Should -BeGreaterThan 0
            $dialogClass.ToString() | Should -Be "#32770"
            # Acknowledge only the duplicate notice owned by this isolated runtime fixture.
            $deadline = (Get-Date).AddSeconds(5)
            do {
                $duplicateProcess.Refresh()
                $acceptButton = [JameWindowProbe]::GetDlgItem($duplicateProcess.MainWindowHandle, 1)
                $controlError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($acceptButton -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 100 }
            } while ($acceptButton -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)
            $controls = [JameWindowProbe]::DescribeChildren($duplicateProcess.MainWindowHandle)
            $acceptButton | Should -Not -Be ([IntPtr]::Zero) -Because "the notice must have an OK button (Win32 error $controlError; children: $controls)"
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
            $windowProcess.Refresh()
            $windowProcess.HasExited | Should -BeFalse

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
        }
    }
}

BeforeAll {
    $sourceExe = $env:JAMEFIREWALL_EXE
    if ([string]::IsNullOrWhiteSpace($sourceExe)) {
        throw "JAMEFIREWALL_EXE is required."
    }

    $resolvedExe = (Resolve-Path $sourceExe).Path
    $runtimeDir = Join-Path $TestDrive "portable-runtime"
    New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null

    $script:runtimeExe = Join-Path $runtimeDir "JameFirewall.exe"
    Copy-Item $resolvedExe $script:runtimeExe

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    $script:isAdmin = $principal.IsInRole($adminRole)
}

Describe "JameFirewall packaged Windows runtime" {
    It "runs from an isolated directory with no project Python on PATH" {
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

            $crashLog = Join-Path (Split-Path $script:runtimeExe) "crash_log.txt"
            Test-Path $crashLog | Should -BeFalse
        }
        finally {
            $env:PATH = $oldPath
            Get-Process -Name "JameFirewall" -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.StartTime -ge $startedAfter -and
                    $_.Path -eq $script:runtimeExe
                } |
                Stop-Process -Force -ErrorAction SilentlyContinue

            Get-Process -Name "JameFirewall" -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.StartTime -ge $startedAfter -and
                    $_.Path -eq $script:runtimeExe
                } |
                Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
        }
    }
}

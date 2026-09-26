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
        $env:PATH = @(
            "$env:SystemRoot\System32"
            "$env:SystemRoot"
            "$env:SystemRoot\System32\Wbem"
            "$env:SystemRoot\System32\WindowsPowerShell\v1.0"
        ) -join ";"

        $process = $null
        try {
            $process = Start-Process -FilePath $script:runtimeExe -WorkingDirectory (Split-Path $script:runtimeExe) -PassThru

            $deadline = (Get-Date).AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 250
                $process.Refresh()
            } while (
                -not $process.HasExited -and
                $process.MainWindowHandle -eq 0 -and
                (Get-Date) -lt $deadline
            )

            $process.HasExited | Should -BeFalse
            $process.MainWindowHandle | Should -Not -Be 0
            $process.MainWindowTitle | Should -Be "JameFirewall"

            $crashLog = Join-Path (Split-Path $script:runtimeExe) "crash_log.txt"
            Test-Path $crashLog | Should -BeFalse
        }
        finally {
            $env:PATH = $oldPath
            if ($null -ne $process -and -not $process.HasExited) {
                Stop-Process -Id $process.Id -Force
            }
        }
    }
}

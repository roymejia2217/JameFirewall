"""Bounded provider-scoped inventory script; no partial result proves protection."""

MAX_QUERY_ROWS = 8192
MAX_SUFFIXES = 8
MAX_SUFFIX_LENGTH = 64

_INVENTORY_SCRIPT = r"""
function Test-Any($value) {
    $values = @($value)
    return ($values.Count -eq 1 -and [string]$values[0] -eq 'Any')
}
function Test-Unrestricted($rule, $application, $port, $address, $service, $interface, $type, $security) {
    return (
        [string]$port.Protocol -in @('Any', '256') -and
        (Test-Any $port.LocalPort) -and (Test-Any $port.RemotePort) -and
        (Test-Any $port.IcmpType) -and (Test-Any $port.DynamicTarget) -and
        (Test-Any $address.LocalAddress) -and (Test-Any $address.RemoteAddress) -and
        (Test-Any $service.Service) -and (Test-Any $interface.InterfaceAlias) -and
        (Test-Any $type.InterfaceType) -and
        [string]$security.Authentication -eq 'NotRequired' -and
        [string]$security.Encryption -eq 'NotRequired' -and
        [string]$security.LocalUser -in @('', 'Any') -and
        [string]$security.RemoteUser -in @('', 'Any') -and
        [string]$security.RemoteMachine -in @('', 'Any') -and
        [string]$application.Package -in @('', 'Any') -and
        @($rule.Platform | Where-Object { $_ }).Count -eq 0 -and
        @($rule.RemoteDynamicKeywordAddresses | Where-Object { $_ }).Count -eq 0 -and
        [string]$rule.PolicyAppId -eq ''
    )
}
# Only provider-filtered rows cross into this command. Every emitted row consumes budget,
# including overlaps across selectors. Never return truncated inventories.
$counts = @{ Rows = 0 }
function Read-Candidates($store, $parameter, $pattern, $target) {
    $selector = @{}; $selector[$parameter] = $pattern
    $seen = @{}
    try {
        Get-NetFirewallRule -PolicyStore $store @selector -ErrorAction Stop | ForEach-Object {
            $r = $_
            $counts.Rows++
            if ($counts.Rows -gt $maxRows) { throw 'Inventory query row limit exceeded' }
            if (-not $r.Name -or $seen.ContainsKey($r.Name)) {
                throw 'Ambiguous native rule identity'
            }
            $seen[$r.Name] = $true
            if ($seen.Count -gt $maxCandidates) { throw 'Inventory candidate limit exceeded' }
            if ($target.ContainsKey($r.Name)) {
                $prior = $target[$r.Name]
                foreach ($field in @('Name', 'DisplayName', 'Group', 'Direction', 'Action',
                    'Enabled', 'Profile', 'PolicyStoreSource', 'PolicyStoreSourceType')) {
                    if (-not [string]::Equals([string]$prior.$field, [string]$r.$field,
                        [StringComparison]::Ordinal)) { throw 'Inventory changed during query' }
                }
            } else {
                if ($target.Count -ge $maxCandidates) { throw 'Inventory candidate limit exceeded' }
                $target[$r.Name] = $r
            }
        }
    } catch {
        # NetSecurity reports exact-selector absence as ObjectNotFound. Accept only that
        # provider identity, with no rows emitted; access/CIM/transport/quota failures propagate.
        $nativeProperty = @{ Group = 'RuleGroup'; Name = 'InstanceID'; DisplayName = 'DisplayName' }[$parameter]
        $emptyId = 'CmdletizationQuery_NotFound_' + $nativeProperty + ',Get-NetFirewallRule'
        if ($seen.Count -ne 0 -or $_.CategoryInfo.Category -ne 'ObjectNotFound' -or
            $_.FullyQualifiedErrorId -ne $emptyId) { throw }
    }
}
$local = @{}
Read-Candidates 'PersistentStore' 'Group' $group $local
foreach ($suffix in $suffixes) {
    Read-Candidates 'PersistentStore' 'Name' ($suffix + ':v1:*') $local
    Read-Candidates 'PersistentStore' 'DisplayName' ('* ' + $suffix) $local
}
$active = @{}
Read-Candidates 'ActiveStore' 'Group' $group $active
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3) { throw 'Incomplete firewall profile inventory' }
$enabled = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0
$allowed = @($profiles | Where-Object {
    [string]$_.AllowLocalFirewallRules -eq 'False'
}).Count -eq 0
$localRules = @(foreach ($r in $local.Values) {
    $candidate = $r.Group -eq $group
    foreach ($suffix in $suffixes) {
        if ($r.Name.StartsWith($suffix + ':v1:', [StringComparison]::Ordinal) -or
            $r.DisplayName.EndsWith(' ' + $suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $candidate = $true
        }
    }
    if ($candidate) { $r }
})
# NetSecurity declares a one-to-one association and accepts rule objects through pipeline input.
# Keep the output in the same sequential order, assert cardinality, then verify program paths
# against their rule identities before trusting the corresponding traffic filters.
$localApplications = @($localRules | Get-NetFirewallApplicationFilter -ErrorAction Stop)
if ($localApplications.Count -ne $localRules.Count) { throw 'Incomplete application filter inventory' }
$localPrograms = @{}
for ($index = 0; $index -lt $localRules.Count; $index++) {
    $localPrograms[$localRules[$index].Name] = [Environment]::ExpandEnvironmentVariables(
        [string]$localApplications[$index].Program)
}

# A rule that fails a necessary ActiveStore property cannot be effective. Skip associated
# filter reads for it; continue to inspect every candidate that could enforce a block.
$activeCandidates = @(foreach ($r in $localRules) {
    $a = $active[$r.Name]
    if ($null -ne $a -and $a.Group -eq $group -and
        [string]$a.Enabled -eq 'True' -and [string]$a.Action -eq 'Block' -and
        [string]$a.Profile -eq 'Any' -and [string]$a.PrimaryStatus -eq 'OK' -and
        $a.Direction -eq $r.Direction) { $a }
})
$activeApplications = @($activeCandidates | Get-NetFirewallApplicationFilter -ErrorAction Stop)
if ($activeApplications.Count -ne $activeCandidates.Count) {
    throw 'Incomplete active application filter inventory'
}
$effectiveCandidates = @(for ($index = 0; $index -lt $activeCandidates.Count; $index++) {
    $a = $activeCandidates[$index]
    $program = [Environment]::ExpandEnvironmentVariables([string]$activeApplications[$index].Program)
    $localProgram = [string]$localPrograms[$a.Name]
    if ([string]::Equals($program.Replace('/', '\'), $localProgram.Replace('/', '\'),
        [StringComparison]::OrdinalIgnoreCase)) {
        [PSCustomObject]@{ Rule = $a; Application = $activeApplications[$index] }
    }
})
$effectiveRules = @($effectiveCandidates | ForEach-Object { $_.Rule })
$ports = @($effectiveRules | Get-NetFirewallPortFilter -ErrorAction Stop)
$addresses = @($effectiveRules | Get-NetFirewallAddressFilter -ErrorAction Stop)
$services = @($effectiveRules | Get-NetFirewallServiceFilter -ErrorAction Stop)
$interfaces = @($effectiveRules | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
$interfaceTypes = @($effectiveRules | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
$securityFilters = @($effectiveRules | Get-NetFirewallSecurityFilter -ErrorAction Stop)
if ($ports.Count -ne $effectiveCandidates.Count -or
    $addresses.Count -ne $effectiveCandidates.Count -or
    $services.Count -ne $effectiveCandidates.Count -or
    $interfaces.Count -ne $effectiveCandidates.Count -or
    $interfaceTypes.Count -ne $effectiveCandidates.Count -or
    $securityFilters.Count -ne $effectiveCandidates.Count) {
    throw 'Incomplete traffic filter inventory'
}
$effectiveByName = @{}
for ($index = 0; $index -lt $effectiveCandidates.Count; $index++) {
    $candidate = $effectiveCandidates[$index]
    $a = $candidate.Rule
    $effectiveByName[$a.Name] = [bool](Test-Unrestricted $a $candidate.Application `
        $ports[$index] $addresses[$index] $services[$index] $interfaces[$index] `
        $interfaceTypes[$index] $securityFilters[$index])
}
$items = @(for ($index = 0; $index -lt $localRules.Count; $index++) {
    $r = $localRules[$index]
    $program = [string]$localPrograms[$r.Name]
    $effective = $effectiveByName.ContainsKey($r.Name) -and [bool]$effectiveByName[$r.Name]
    $states = @()
    $a = $active[$r.Name]
    if ($null -ne $a) {
        # NetSecurity exposes an array through the Value property on Windows PowerShell.
        $enforcement = $a.EnforcementStatus
        if ($null -ne $enforcement -and
            $null -ne $enforcement.PSObject.Properties['Value']) {
            $enforcement = $enforcement.Value
        }
        $states = @($enforcement | ForEach-Object { [string]$_ })
    }
    [PSCustomObject]@{
        Name = [string]$r.Name; DisplayName = [string]$r.DisplayName
        Program = $program; Direction = [string]$r.Direction
        Action = [string]$r.Action; Group = [string]$r.Group
        Enabled = ([string]$r.Enabled -eq 'True')
        Profile = [string]$r.Profile; Effective = [bool]$effective
        EnforcementStates = @($states)
    }
})
[PSCustomObject]@{
    Complete = $true; Rules = @($items); ProfilesEnabled = [bool]$enabled; LocalRulesAllowed = [bool]$allowed
} | ConvertTo-Json -Depth 4 -Compress
"""

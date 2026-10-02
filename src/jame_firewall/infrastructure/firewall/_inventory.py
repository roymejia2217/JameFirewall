"""Provider-scoped firewall inventory; no partial result proves protection."""

MAX_SUFFIXES = 8
MAX_SUFFIX_LENGTH = 64

_INVENTORY_SCRIPT = r"""
function Test-Any($value) {
    $values = @($value)
    return ($values.Count -eq 1 -and [string]$values[0] -eq 'Any')
}
function Test-Unrestricted(
    $rule, $application, $port, $address, $service, $interface, $type, $security
) {
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
function Read-FilterIndex($store, $commandName, $expected, $label) {
    $indexed = @{}
    if ($expected.Count -eq 0) { return $indexed }
    & $commandName -PolicyStore $store -All -ErrorAction Stop | ForEach-Object {
        $item = $_
        $identity = [string]$item.InstanceID
        if ($expected.ContainsKey($identity)) {
            if (-not $identity -or $indexed.ContainsKey($identity)) {
                throw ('Ambiguous ' + $label + ' identity')
            }
            $indexed[$identity] = $item
        }
    }
    if ($indexed.Count -ne $expected.Count) {
        throw ('Incomplete ' + $label + ' inventory')
    }
    return $indexed
}
# Rule selectors remain provider-scoped. Overlaps are identity-checked, and provider
# errors or inconsistent snapshots fail the whole inventory.
function Read-Candidates($store, $parameter, $pattern, $target) {
    $selector = @{}; $selector[$parameter] = $pattern
    $seen = @{}
    try {
        Get-NetFirewallRule -PolicyStore $store @selector -ErrorAction Stop | ForEach-Object {
            $r = $_
            if (-not $r.Name -or $seen.ContainsKey($r.Name)) {
                throw 'Ambiguous native rule identity'
            }
            $seen[$r.Name] = $true
            if ($target.ContainsKey($r.Name)) {
                $prior = $target[$r.Name]
                foreach ($field in @('Name', 'DisplayName', 'Group', 'Direction', 'Action',
                    'Enabled', 'Profile', 'PolicyStoreSource', 'PolicyStoreSourceType')) {
                    if (-not [string]::Equals([string]$prior.$field, [string]$r.$field,
                        [StringComparison]::Ordinal)) { throw 'Inventory changed during query' }
                }
            } else {
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
$active = @{}
foreach ($suffix in $suffixes) {
    Read-Candidates 'PersistentStore' 'Name' ($suffix + ':v1:*') $local
    Read-Candidates 'PersistentStore' 'DisplayName' ('* ' + $suffix) $local
    Read-Candidates 'ActiveStore' 'Name' ($suffix + ':v1:*') $active
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3) { throw 'Incomplete firewall profile inventory' }
$enabled = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0
$allowed = @($profiles | Where-Object {
    [string]$_.AllowLocalFirewallRules -eq 'False'
}).Count -eq 0
$localRules = @($local.Values)
$localApplicationById = Read-FilterIndex 'PersistentStore' `
    'Get-NetFirewallApplicationFilter' $local 'application filter'

# NetSecurity filter objects expose the associated rule identity as InstanceID. Read each policy
# store catalog once and join only the expected rules by identity. This avoids the provider's
# per-associated-rule lookup path without trusting pipeline output order.
$activeCandidates = @($active.Values | Where-Object {
    $local.ContainsKey($_.Name) -and $_.Group -eq $group -and
    [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Block' -and
    [string]$_.Profile -eq 'Any' -and [string]$_.PrimaryStatus -eq 'OK'
})
$activeExpected = @{}
foreach ($a in $activeCandidates) { $activeExpected[$a.Name] = $a }
$activeApplicationById = Read-FilterIndex 'ActiveStore' `
    'Get-NetFirewallApplicationFilter' $activeExpected 'active application filter'
$ports = Read-FilterIndex 'ActiveStore' 'Get-NetFirewallPortFilter' `
    $activeExpected 'port filter'
$addresses = Read-FilterIndex 'ActiveStore' 'Get-NetFirewallAddressFilter' `
    $activeExpected 'address filter'
$services = Read-FilterIndex 'ActiveStore' 'Get-NetFirewallServiceFilter' `
    $activeExpected 'service filter'
$interfaces = Read-FilterIndex 'ActiveStore' 'Get-NetFirewallInterfaceFilter' `
    $activeExpected 'interface filter'
$interfaceTypes = Read-FilterIndex 'ActiveStore' 'Get-NetFirewallInterfaceTypeFilter' `
    $activeExpected 'interface type filter'
$securityFilters = Read-FilterIndex 'ActiveStore' 'Get-NetFirewallSecurityFilter' `
    $activeExpected 'security filter'

$effectiveByName = @{}
foreach ($a in $activeCandidates) {
    $af = $activeApplicationById[$a.Name]
    $localFilter = $localApplicationById[$a.Name]
    $ap = [Environment]::ExpandEnvironmentVariables([string]$af.Program)
    $program = [Environment]::ExpandEnvironmentVariables([string]$localFilter.Program)
    $effectiveByName[$a.Name] = [bool](
        $a.Direction -eq $local[$a.Name].Direction -and
        [string]::Equals($ap.Replace('/', '\'), $program.Replace('/', '\'),
            [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Unrestricted $a $af $ports[$a.Name] $addresses[$a.Name] $services[$a.Name] `
            $interfaces[$a.Name] $interfaceTypes[$a.Name] $securityFilters[$a.Name])
    )
}

$items = @(foreach ($r in $localRules) {
    $filter = $localApplicationById[$r.Name]
    $program = [Environment]::ExpandEnvironmentVariables([string]$filter.Program)
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
        Profile = [string]$r.Profile
        Effective = ($effectiveByName.ContainsKey($r.Name) -and [bool]$effectiveByName[$r.Name])
        EnforcementStates = @($states)
    }
})
[PSCustomObject]@{
    Complete = $true; Rules = @($items); ProfilesEnabled = [bool]$enabled; LocalRulesAllowed = [bool]$allowed
} | ConvertTo-Json -Depth 4 -Compress
"""

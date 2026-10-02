"""Provider-scoped firewall inventory; no partial result proves protection."""

MAX_SUFFIXES = 8
MAX_SUFFIX_LENGTH = 64

_INVENTORY_SCRIPT = r"""
function Test-Any($value) {
    $values = @($value)
    return ($values.Count -eq 1 -and [string]$values[0] -eq 'Any')
}
function Test-Unrestricted($rule, $application) {
    $port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule)
    $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule)
    $service = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule)
    $interface = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule)
    $type = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule)
    $security = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule)
    if ($port.Count -ne 1 -or $address.Count -ne 1 -or $service.Count -ne 1 -or
        $interface.Count -ne 1 -or $type.Count -ne 1 -or $security.Count -ne 1) {
        throw 'Incomplete traffic filter'
    }
    return (
        [string]$port[0].Protocol -in @('Any', '256') -and
        (Test-Any $port[0].LocalPort) -and (Test-Any $port[0].RemotePort) -and
        (Test-Any $port[0].IcmpType) -and (Test-Any $port[0].DynamicTarget) -and
        (Test-Any $address[0].LocalAddress) -and (Test-Any $address[0].RemoteAddress) -and
        (Test-Any $service[0].Service) -and (Test-Any $interface[0].InterfaceAlias) -and
        (Test-Any $type[0].InterfaceType) -and
        [string]$security[0].Authentication -eq 'NotRequired' -and
        [string]$security[0].Encryption -eq 'NotRequired' -and
        [string]$security[0].LocalUser -in @('', 'Any') -and
        [string]$security[0].RemoteUser -in @('', 'Any') -and
        [string]$security[0].RemoteMachine -in @('', 'Any') -and
        [string]$application.Package -in @('', 'Any') -and
        @($rule.Platform | Where-Object { $_ }).Count -eq 0 -and
        @($rule.RemoteDynamicKeywordAddresses | Where-Object { $_ }).Count -eq 0 -and
        [string]$rule.PolicyAppId -eq ''
    )
}
# Only provider-filtered rows cross into this command. Overlaps are identity-checked,
# and provider errors or inconsistent snapshots fail the whole inventory.
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
$items = @(foreach ($r in $local.Values) {
    $candidate = $r.Group -eq $group
    foreach ($suffix in $suffixes) {
        if ($r.Name.StartsWith($suffix + ':v1:', [StringComparison]::Ordinal) -or
            $r.DisplayName.EndsWith(' ' + $suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $candidate = $true
        }
    }
    if (-not $candidate) { continue }
    $filter = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r)
    if ($filter.Count -ne 1) { throw 'Incomplete application filter' }
    $program = [Environment]::ExpandEnvironmentVariables([string]$filter[0].Program)
    $effective = $false
    $states = @()
    $a = $active[$r.Name]
    if ($null -ne $a) {
        $af = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $a)
        if ($af.Count -ne 1) { throw 'Incomplete active application filter' }
        $ap = [Environment]::ExpandEnvironmentVariables([string]$af[0].Program)
        # NetSecurity exposes an array through the Value property on Windows PowerShell.
        $enforcement = $a.EnforcementStatus
        if ($null -ne $enforcement -and
            $null -ne $enforcement.PSObject.Properties['Value']) {
            $enforcement = $enforcement.Value
        }
        $states = @($enforcement | ForEach-Object { [string]$_ })
        $effective = (
            $a.Group -eq $group -and
            [string]$a.Enabled -eq 'True' -and
            [string]$a.Action -eq 'Block' -and
            [string]$a.Profile -eq 'Any' -and
            [string]$a.PrimaryStatus -eq 'OK' -and
            (Test-Unrestricted $a $af[0]) -and
            $a.Direction -eq $r.Direction -and
            [string]::Equals($ap.Replace('/', '\'), $program.Replace('/', '\'),
                [StringComparison]::OrdinalIgnoreCase)
        )
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

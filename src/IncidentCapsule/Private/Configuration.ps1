function Get-ICDefaultEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Minimal', 'Standard', 'Extended')]
        [string]$Profile
    )

    $minimal = @(
        'System',
        'Application',
        'Security',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
    )

    $standardAdditional = @(
        'Windows PowerShell',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-CodeIntegrity/Operational',
        'Microsoft-Windows-Bits-Client/Operational'
    )

    $extendedAdditional = @(
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
        'Microsoft-Windows-SMBServer/Security',
        'Microsoft-Windows-Kernel-PnP/Configuration',
        'Microsoft-Windows-GroupPolicy/Operational'
    )

    switch ($Profile) {
        'Minimal'  { return $minimal }
        'Standard' { return @($minimal + $standardAdditional | Select-Object -Unique) }
        'Extended' { return @($minimal + $standardAdditional + $extendedAdditional | Select-Object -Unique) }
    }
}

function Get-ICDefaultConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Minimal', 'Standard', 'Extended')]
        [string]$Profile
    )

    $allCollectors = @($script:ICCollectorDefinitions.Keys)

    switch ($Profile) {
        'Minimal' {
            return [ordered]@{
                Collectors                   = @('System', 'Storage', 'Processes', 'Services', 'Network', 'Sessions', 'LocalAccounts', 'Defender', 'PowerShell', 'SecurityConfiguration', 'EventLogs')
                EventLogs                    = @(Get-ICDefaultEventLogs -Profile Minimal)
                EventLookbackHours           = 12
                MaximumEventsPerLog          = 250
                ExportEvtx                   = $false
                ExportScheduledTaskXml       = $false
                IncludeProcessCommandLines   = $true
                HashProcessExecutables       = $false
                MaximumExecutableHashes      = 50
                HashPersistenceFiles         = $false
                CollectWmiSubscriptions      = $false
                CollectDefenderPreferences   = $true
                CollectWindowsUpdateHistory  = $false
                MaximumWindowsUpdateHistory  = 100
                CollectSignedDrivers         = $false
                MaximumSignedDrivers         = 2500
                MaximumFirewallRules         = 2000
            }
        }
        'Standard' {
            return [ordered]@{
                Collectors                   = $allCollectors
                EventLogs                    = @(Get-ICDefaultEventLogs -Profile Standard)
                EventLookbackHours           = 24
                MaximumEventsPerLog          = 1000
                ExportEvtx                   = $true
                ExportScheduledTaskXml       = $true
                IncludeProcessCommandLines   = $true
                HashProcessExecutables       = $false
                MaximumExecutableHashes      = 150
                HashPersistenceFiles         = $true
                CollectWmiSubscriptions      = $true
                CollectDefenderPreferences   = $true
                CollectWindowsUpdateHistory  = $true
                MaximumWindowsUpdateHistory  = 200
                CollectSignedDrivers         = $false
                MaximumSignedDrivers         = 5000
                MaximumFirewallRules         = 5000
            }
        }
        'Extended' {
            return [ordered]@{
                Collectors                   = $allCollectors
                EventLogs                    = @(Get-ICDefaultEventLogs -Profile Extended)
                EventLookbackHours           = 72
                MaximumEventsPerLog          = 5000
                ExportEvtx                   = $true
                ExportScheduledTaskXml       = $true
                IncludeProcessCommandLines   = $true
                HashProcessExecutables       = $true
                MaximumExecutableHashes      = 300
                HashPersistenceFiles         = $true
                CollectWmiSubscriptions      = $true
                CollectDefenderPreferences   = $true
                CollectWindowsUpdateHistory  = $true
                MaximumWindowsUpdateHistory  = 500
                CollectSignedDrivers         = $true
                MaximumSignedDrivers         = 10000
                MaximumFirewallRules         = 10000
            }
        }
    }
}

function Copy-ICValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $copy[$key] = Copy-ICValue -Value $Value[$key]
        }
        return $copy
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        return @($Value | ForEach-Object { Copy-ICValue -Value $_ })
    }

    return $Value
}

function Merge-ICHashtable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Base,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Override
    )

    $result = Copy-ICValue -Value $Base
    foreach ($key in $Override.Keys) {
        if (
            $result.Contains($key) -and
            $result[$key] -is [System.Collections.IDictionary] -and
            $Override[$key] -is [System.Collections.IDictionary]
        ) {
            $result[$key] = Merge-ICHashtable -Base $result[$key] -Override $Override[$key]
        }
        else {
            $result[$key] = Copy-ICValue -Value $Override[$key]
        }
    }

    return $result
}

function Test-ICConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $unknown = @($Configuration.Keys | Where-Object { $_ -notin $script:ICConfigurationKeys })
    if ($unknown.Count -gt 0) {
        throw "Unknown configuration key(s): $($unknown -join ', ')."
    }

    $unknownCollectors = @($Configuration.Collectors | Where-Object { $_ -notin $script:ICCollectorDefinitions.Keys })
    if ($unknownCollectors.Count -gt 0) {
        throw "Unknown collector name(s): $($unknownCollectors -join ', ')."
    }

    if (@($Configuration.Collectors).Count -eq 0) {
        throw 'At least one collector must be selected.'
    }

    if (@($Configuration.EventLogs | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
        throw 'EventLogs cannot contain empty names.'
    }

    foreach ($key in @(
        'EventLookbackHours', 'MaximumEventsPerLog', 'MaximumExecutableHashes',
        'MaximumWindowsUpdateHistory', 'MaximumSignedDrivers', 'MaximumFirewallRules'
    )) {
        $value = $Configuration[$key]
        if ($value -isnot [int] -and $value -isnot [long]) {
            throw "Configuration key '$key' must be an integer."
        }
        if ([int64]$value -lt 1) {
            throw "Configuration key '$key' must be greater than zero."
        }
    }

    foreach ($key in @(
        'ExportEvtx', 'ExportScheduledTaskXml', 'IncludeProcessCommandLines',
        'HashProcessExecutables', 'HashPersistenceFiles', 'CollectWmiSubscriptions',
        'CollectDefenderPreferences', 'CollectWindowsUpdateHistory', 'CollectSignedDrivers'
    )) {
        if ($Configuration[$key] -isnot [bool]) {
            throw "Configuration key '$key' must be Boolean."
        }
    }

    return $true
}

function Resolve-ICConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Minimal', 'Standard', 'Extended')]
        [string]$Profile,

        [string]$ConfigurationPath,

        [string[]]$Collectors,

        [string[]]$ExcludeCollector
    )

    $configuration = Get-ICDefaultConfiguration -Profile $Profile

    if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
        if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
            throw "Configuration file '$ConfigurationPath' does not exist."
        }

        $override = Import-PowerShellDataFile -LiteralPath $ConfigurationPath
        $configuration = Merge-ICHashtable -Base $configuration -Override $override
    }

    if ($null -ne $Collectors -and $Collectors.Count -gt 0) {
        $configuration.Collectors = @($Collectors | Select-Object -Unique)
    }

    if ($null -ne $ExcludeCollector -and $ExcludeCollector.Count -gt 0) {
        $configuration.Collectors = @($configuration.Collectors | Where-Object { $_ -notin $ExcludeCollector })
    }

    $configuration.Collectors = @($configuration.Collectors | Select-Object -Unique)
    $configuration.EventLogs = @($configuration.EventLogs | Select-Object -Unique)

    [void](Test-ICConfiguration -Configuration $configuration)
    return $configuration
}

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
        'Microsoft-Windows-GroupPolicy/Operational',
        'Microsoft-Windows-WinRM/Operational',
        'Microsoft-Windows-PrintService/Operational',
        'OpenSSH/Operational'
    )

    switch ($Profile) {
        'Minimal'  { return $minimal }
        'Standard' { return @($minimal + $standardAdditional | Select-Object -Unique) }
        'Extended' { return @($minimal + $standardAdditional + $extendedAdditional | Select-Object -Unique) }
    }
}

function New-ICCommonConfiguration {
    [CmdletBinding()]
    param()

    return [ordered]@{
        SpreadsheetSafeCsv              = $true
        MaximumArchiveEntries           = 20000
        MaximumArchiveEntryBytes        = 1073741824L
        MaximumArchiveExpandedBytes     = 21474836480L
        MaximumArchiveCompressionRatio  = 250
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
    $common = New-ICCommonConfiguration

    $profileConfiguration = switch ($Profile) {
        'Minimal' {
            [ordered]@{
                Collectors                   = @('System', 'Storage', 'Processes', 'Services', 'Network', 'Sessions', 'LocalAccounts', 'Defender', 'PowerShell', 'SecurityConfiguration', 'EventLogs', 'InstalledSoftware', 'Certificates')
                EventLogs                    = @(Get-ICDefaultEventLogs -Profile Minimal)
                EventLookbackHours           = 12
                MaximumEventsPerLog          = 250
                MaximumCapsuleBytes          = 1073741824L
                MaximumEvtxBytesPerLog       = 67108864L
                NativeCommandTimeoutSeconds  = 30
                MaximumNativeOutputBytes     = 10485760L
                MaximumTimelineEntries       = 2000
                DataHandlingProfile          = 'Minimized'
                ExportEvtx                   = $false
                ExportScheduledTaskXml       = $false
                IncludeProcessCommandLines   = $false
                HashProcessExecutables       = $false
                MaximumExecutableHashes      = 50
                HashPersistenceFiles         = $false
                CollectWmiSubscriptions      = $false
                CollectDefenderPreferences   = $false
                CollectWindowsUpdateHistory  = $false
                MaximumWindowsUpdateHistory  = 100
                CollectSignedDrivers         = $false
                MaximumSignedDrivers         = 2500
                MaximumFirewallRules         = 2000
                MaximumEventMessageChars     = 4096
                MaximumPrefetchFiles         = 256
                MaximumArtifactFileBytes     = 8388608L
            }
        }
        'Standard' {
            [ordered]@{
                Collectors                   = $allCollectors
                EventLogs                    = @(Get-ICDefaultEventLogs -Profile Standard)
                EventLookbackHours           = 24
                MaximumEventsPerLog          = 1000
                MaximumCapsuleBytes          = 5368709120L
                MaximumEvtxBytesPerLog       = 268435456L
                NativeCommandTimeoutSeconds  = 60
                MaximumNativeOutputBytes     = 26214400L
                MaximumTimelineEntries       = 10000
                DataHandlingProfile          = 'Full'
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
                MaximumEventMessageChars     = 8192
                MaximumPrefetchFiles         = 512
                MaximumArtifactFileBytes     = 33554432L
            }
        }
        'Extended' {
            [ordered]@{
                Collectors                   = $allCollectors
                EventLogs                    = @(Get-ICDefaultEventLogs -Profile Extended)
                EventLookbackHours           = 72
                MaximumEventsPerLog          = 5000
                MaximumCapsuleBytes          = 21474836480L
                MaximumEvtxBytesPerLog       = 1073741824L
                NativeCommandTimeoutSeconds  = 120
                MaximumNativeOutputBytes     = 104857600L
                MaximumTimelineEntries       = 50000
                DataHandlingProfile          = 'Full'
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
                MaximumEventMessageChars     = 16384
                MaximumPrefetchFiles         = 1024
                MaximumArtifactFileBytes     = 134217728L
            }
        }
    }

    foreach ($key in $common.Keys) {
        $profileConfiguration[$key] = $common[$key]
    }

    return $profileConfiguration
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

    $missing = @($script:ICConfigurationKeys | Where-Object { -not $Configuration.Contains($_) })
    if ($missing.Count -gt 0) {
        throw "Missing configuration key(s): $($missing -join ', ')."
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

    foreach ($key in $script:ICConfigurationLimits.Keys) {
        $value = $Configuration[$key]
        if ($value -isnot [int] -and $value -isnot [long]) {
            throw "Configuration key '$key' must be an integer."
        }
        $minimum = [int64]$script:ICConfigurationLimits[$key].Minimum
        $maximum = [int64]$script:ICConfigurationLimits[$key].Maximum
        if ([int64]$value -lt $minimum) {
            throw "Configuration key '$key' must be between $minimum and $maximum."
        }
        if ([int64]$value -gt $maximum) {
            throw "Configuration key '$key' exceeds the supported maximum of $maximum and must be between $minimum and $maximum."
        }
    }

    if ($Configuration.DataHandlingProfile -isnot [string] -or $Configuration.DataHandlingProfile -notin @('Full', 'Minimized')) {
        throw "Configuration key 'DataHandlingProfile' must be 'Full' or 'Minimized'."
    }

    if ([int64]$Configuration.MaximumArchiveExpandedBytes -lt [int64]$Configuration.MaximumCapsuleBytes) {
        throw "Configuration key 'MaximumArchiveExpandedBytes' must be greater than or equal to MaximumCapsuleBytes."
    }
    if ([int64]$Configuration.MaximumArchiveEntryBytes -gt [int64]$Configuration.MaximumArchiveExpandedBytes) {
        throw "Configuration key 'MaximumArchiveEntryBytes' cannot exceed MaximumArchiveExpandedBytes."
    }
    if ([int64]$Configuration.MaximumArchiveEntryBytes -lt [int64]$Configuration.MaximumEvtxBytesPerLog) {
        throw "Configuration key 'MaximumArchiveEntryBytes' must be greater than or equal to MaximumEvtxBytesPerLog."
    }

    foreach ($key in @(
        'ExportEvtx', 'ExportScheduledTaskXml', 'IncludeProcessCommandLines',
        'HashProcessExecutables', 'HashPersistenceFiles', 'CollectWmiSubscriptions',
        'CollectDefenderPreferences', 'CollectWindowsUpdateHistory', 'CollectSignedDrivers',
        'SpreadsheetSafeCsv'
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
    $explicitConfigurationKeys = @()

    if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
        if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
            throw "Configuration file '$ConfigurationPath' does not exist."
        }

        $override = Import-PowerShellDataFile -LiteralPath $ConfigurationPath
        $explicitConfigurationKeys = @($override.Keys)
        $configuration = Merge-ICHashtable -Base $configuration -Override $override
    }

    if ($configuration.DataHandlingProfile -eq 'Minimized') {
        foreach ($sensitiveKey in @(
            'IncludeProcessCommandLines', 'ExportScheduledTaskXml',
            'CollectDefenderPreferences', 'CollectWindowsUpdateHistory'
        )) {
            if ($sensitiveKey -notin $explicitConfigurationKeys) {
                $configuration[$sensitiveKey] = $false
            }
        }
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

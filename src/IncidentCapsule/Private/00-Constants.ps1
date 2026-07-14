$moduleRoot = Split-Path $PSScriptRoot -Parent
$moduleManifestPath = Join-Path $moduleRoot 'IncidentCapsule.psd1'
$moduleManifestData = Import-PowerShellDataFile -LiteralPath $moduleManifestPath

$script:ICName = 'Incident Capsule'
$script:ICVersion = [string]$moduleManifestData.ModuleVersion
$script:ICSchemaVersion = '1.0'
$script:ICCollectorSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/collector-envelope.schema.json"
$script:ICCapsuleSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/capsule.schema.json"
$script:ICManifestSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/manifest.schema.json"

$script:ICCollectorDefinitions = [ordered]@{
    System = [ordered]@{
        Function    = 'Get-ICSystemEvidence'
        Description = 'Host identity, operating system, hardware, boot, clock, Secure Boot, TPM, and execution identity.'
    }
    Storage = [ordered]@{
        Function    = 'Get-ICStorageEvidence'
        Description = 'Disk, volume, SMB share, and BitLocker state.'
    }
    Processes = [ordered]@{
        Function    = 'Get-ICProcessEvidence'
        Description = 'Running process metadata, parent relationships, owners, command lines, and optional executable hashes.'
    }
    Services = [ordered]@{
        Function    = 'Get-ICServiceEvidence'
        Description = 'Service state, startup mode, account, binary path, and process association.'
    }
    Network = [ordered]@{
        Function    = 'Get-ICNetworkEvidence'
        Description = 'Local interfaces, addresses, routes, endpoints, DNS, neighbors, and inbox command snapshots.'
    }
    Sessions = [ordered]@{
        Function    = 'Get-ICSessionEvidence'
        Description = 'Interactive sessions, logon session metadata, and loaded user profiles.'
    }
    LocalAccounts = [ordered]@{
        Function    = 'Get-ICLocalAccountEvidence'
        Description = 'Local users, groups, and group memberships.'
    }
    ScheduledTasks = [ordered]@{
        Function    = 'Get-ICScheduledTaskEvidence'
        Description = 'Scheduled task metadata, actions, triggers, principals, runtime state, and optional XML.'
    }
    Persistence = [ordered]@{
        Function    = 'Get-ICPersistenceEvidence'
        Description = 'Bounded autorun registry locations, startup folders, IFEO debugger values, and WMI subscriptions.'
    }
    Defender = [ordered]@{
        Function    = 'Get-ICDefenderEvidence'
        Description = 'Microsoft Defender status, preferences, ASR state, exclusions, and recent detections.'
    }
    PowerShell = [ordered]@{
        Function    = 'Get-ICPowerShellEvidence'
        Description = 'Engine versions, execution policy, logging configuration, module inventory, and profile metadata.'
    }
    SecurityConfiguration = [ordered]@{
        Function    = 'Get-ICSecurityConfigurationEvidence'
        Description = 'Audit policy, firewall, UAC, RDP, LSA, Device Guard, local security policy, and AppLocker.'
    }
    Hotfixes = [ordered]@{
        Function    = 'Get-ICHotfixEvidence'
        Description = 'QFE records and bounded Windows Update history.'
    }
    Drivers = [ordered]@{
        Function    = 'Get-ICDriverEvidence'
        Description = 'System drivers, optional signed PnP drivers, and driverquery output.'
    }
    EventLogs = [ordered]@{
        Function    = 'Get-ICEventLogEvidence'
        Description = 'Bounded decoded event summaries and optional native EVTX exports.'
    }
}

$script:ICConfigurationKeys = @(
    'Collectors',
    'EventLogs',
    'EventLookbackHours',
    'MaximumEventsPerLog',
    'ExportEvtx',
    'ExportScheduledTaskXml',
    'IncludeProcessCommandLines',
    'HashProcessExecutables',
    'MaximumExecutableHashes',
    'HashPersistenceFiles',
    'CollectWmiSubscriptions',
    'CollectDefenderPreferences',
    'CollectWindowsUpdateHistory',
    'MaximumWindowsUpdateHistory',
    'CollectSignedDrivers',
    'MaximumSignedDrivers',
    'MaximumFirewallRules',
    'SpreadsheetSafeCsv',
    'MaximumArchiveEntries',
    'MaximumArchiveEntryBytes',
    'MaximumArchiveExpandedBytes',
    'MaximumArchiveCompressionRatio'
)

$script:ICConfigurationMaximums = [ordered]@{
    EventLookbackHours              = 720L
    MaximumEventsPerLog             = 100000L
    MaximumExecutableHashes         = 5000L
    MaximumWindowsUpdateHistory     = 10000L
    MaximumSignedDrivers            = 50000L
    MaximumFirewallRules            = 50000L
    MaximumArchiveEntries           = 50000L
    MaximumArchiveEntryBytes        = 2147483648L
    MaximumArchiveExpandedBytes     = 21474836480L
    MaximumArchiveCompressionRatio  = 1000L
}

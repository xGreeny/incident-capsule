$moduleRoot = Split-Path $PSScriptRoot -Parent
$moduleManifestPath = Join-Path $moduleRoot 'IncidentCapsule.psd1'
$moduleManifestData = Import-PowerShellDataFile -LiteralPath $moduleManifestPath

$script:ICName = 'Incident Capsule'
$script:ICVersion = [string]$moduleManifestData.ModuleVersion
$script:ICSchemaVersion = '1.3'
$script:ICCollectorSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/collector-envelope.schema.json"
$script:ICCapsuleSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/capsule.schema.json"
$script:ICManifestSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/manifest.schema.json"
$script:ICCoverageSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/coverage.schema.json"
$script:ICTimelineSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/timeline.schema.json"
$script:ICVerificationReceiptSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/verification-receipt.schema.json"
$script:ICComparisonSchema = "https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/comparison.schema.json"

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
    InstalledSoftware = [ordered]@{
        Function    = 'Get-ICInstalledSoftwareEvidence'
        Description = 'Installed-software inventory from machine and loaded per-user uninstall registry keys.'
    }
    Certificates = [ordered]@{
        Function    = 'Get-ICCertificateEvidence'
        Description = 'Local-machine trust store inventory: root, intermediate, publisher, people, and disallowed certificates.'
    }
    ExecutionArtifacts = [ordered]@{
        Function    = 'Get-ICExecutionArtifactEvidence'
        Description = 'Bounded prefetch copies, raw AppCompatCache export, BAM execution records, and decoded UserAssist entries.'
    }
    Devices = [ordered]@{
        Function    = 'Get-ICDeviceEvidence'
        Description = 'USB storage history, mounted devices, per-user mount points, portable devices, and the bounded device setup log.'
    }
}

# Event channels that are commonly absent because they depend on a third-party
# agent or an optional Windows feature. Their absence is expected and is
# reported as Info coverage rather than a warning that marks EventLogs partial.
$script:ICOptionalEventLogs = @(
    'Microsoft-Windows-Sysmon/Operational',
    'OpenSSH/Operational',
    'Microsoft-Windows-PrintService/Operational'
)

$script:ICConfigurationKeys = @(
    'Collectors',
    'EventLogs',
    'EventLookbackHours',
    'MaximumEventsPerLog',
    'MaximumCapsuleBytes',
    'MaximumEvtxBytesPerLog',
    'NativeCommandTimeoutSeconds',
    'MaximumNativeOutputBytes',
    'MaximumTimelineEntries',
    'DataHandlingProfile',
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
    'MaximumEventMessageChars',
    'MaximumPrefetchFiles',
    'MaximumArtifactFileBytes',
    'SpreadsheetSafeCsv',
    'MaximumArchiveEntries',
    'MaximumArchiveEntryBytes',
    'MaximumArchiveExpandedBytes',
    'MaximumArchiveCompressionRatio'
)

$script:ICConfigurationLimits = [ordered]@{
    EventLookbackHours          = [ordered]@{ Minimum = 1L; Maximum = 720L }
    MaximumEventsPerLog         = [ordered]@{ Minimum = 1L; Maximum = 100000L }
    MaximumCapsuleBytes         = [ordered]@{ Minimum = 1048576L; Maximum = 1099511627776L }
    MaximumEvtxBytesPerLog      = [ordered]@{ Minimum = 1048576L; Maximum = 4294967296L }
    NativeCommandTimeoutSeconds = [ordered]@{ Minimum = 1L; Maximum = 900L }
    MaximumNativeOutputBytes    = [ordered]@{ Minimum = 1024L; Maximum = 1073741824L }
    MaximumTimelineEntries      = [ordered]@{ Minimum = 1L; Maximum = 5000000L }
    MaximumExecutableHashes     = [ordered]@{ Minimum = 1L; Maximum = 10000L }
    MaximumWindowsUpdateHistory = [ordered]@{ Minimum = 1L; Maximum = 10000L }
    MaximumSignedDrivers        = [ordered]@{ Minimum = 1L; Maximum = 100000L }
    MaximumFirewallRules        = [ordered]@{ Minimum = 1L; Maximum = 100000L }
    MaximumEventMessageChars    = [ordered]@{ Minimum = 256L; Maximum = 1048576L }
    MaximumPrefetchFiles        = [ordered]@{ Minimum = 1L; Maximum = 4096L }
    MaximumArtifactFileBytes    = [ordered]@{ Minimum = 65536L; Maximum = 1073741824L }
    MaximumArchiveEntries       = [ordered]@{ Minimum = 1L; Maximum = 50000L }
    MaximumArchiveEntryBytes    = [ordered]@{ Minimum = 1L; Maximum = 1099511627776L }
    MaximumArchiveExpandedBytes = [ordered]@{ Minimum = 1L; Maximum = 8796093022208L }
    MaximumArchiveCompressionRatio = [ordered]@{ Minimum = 1L; Maximum = 1000L }
}

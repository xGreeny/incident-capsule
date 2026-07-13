@{
    EventLookbackHours         = 12
    MaximumEventsPerLog        = 250
    ExportEvtx                 = $false
    ExportScheduledTaskXml     = $false
    IncludeProcessCommandLines = $false
    HashProcessExecutables     = $false
    HashPersistenceFiles       = $false
    CollectDefenderPreferences = $false
    CollectWindowsUpdateHistory = $false
    CollectSignedDrivers       = $false
    EventLogs = @(
        'System',
        'Application',
        'Microsoft-Windows-Windows Defender/Operational'
    )
}

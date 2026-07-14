@{
    DataHandlingProfile        = 'Minimized'
    MaximumCapsuleBytes        = 2147483648
    MaximumTimelineEntries     = 5000
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

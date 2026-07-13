@{
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
}

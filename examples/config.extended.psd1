@{
    DataHandlingProfile          = 'Full'
    MaximumCapsuleBytes          = 21474836480
    MaximumEvtxBytesPerLog       = 1073741824
    NativeCommandTimeoutSeconds  = 120
    MaximumNativeOutputBytes     = 104857600
    MaximumTimelineEntries       = 50000
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

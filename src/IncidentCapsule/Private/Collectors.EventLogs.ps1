function Get-ICEventLogEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $channelRecords = New-Object System.Collections.ArrayList
    $eventTotal = 0
    $availableCount = 0
    $evtxCount = 0
    $startTime = (Get-Date).AddHours(-1 * [double]$Context.Configuration.EventLookbackHours)
    $milliseconds = [int64]$Context.Configuration.EventLookbackHours * 60L * 60L * 1000L
    $wevtutilPath = Get-ICSystemExecutable -Name 'wevtutil.exe'

    foreach ($logName in @($Context.Configuration.EventLogs)) {
        $channelStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $queryMilliseconds = $null
        $evtxExportMilliseconds = $null
        $safeBase = ConvertTo-ICSafeFileName -Value $logName -MaximumLength 80
        $digest = Get-ICShortHash -Value $logName -Length 8
        $fileBase = "$safeBase-$digest"
        $logInfo = $null
        $available = $false

        try {
            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $available = $true
            $availableCount++
        }
        catch {
            Add-ICCollectorWarning -List $warnings -Message "Event channel '$logName' is unavailable: $($_.Exception.Message)"
        }

        $events = @()
        $summaryJsonRelative = "evidence/events/summaries/$fileBase.json"
        $summaryCsvRelative = "evidence/events/summaries/$fileBase.csv"
        $evtxRelative = $null
        $queryError = $null
        $exportError = $null

        if ($available) {
            $queryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $rawEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $startTime } -MaxEvents $Context.Configuration.MaximumEventsPerLog -ErrorAction Stop)
                $events = @($rawEvents | ForEach-Object {
                    $message = $null
                    try { $message = $_.Message } catch { $message = "<message unavailable: $($_.Exception.Message)>" }
                    [pscustomobject][ordered]@{
                        TimeCreatedUtc = ConvertTo-ICIso8601 -Value $_.TimeCreated
                        Id = $_.Id
                        Version = $_.Version
                        Level = $_.Level
                        LevelDisplayName = $_.LevelDisplayName
                        ProviderName = $_.ProviderName
                        ProviderId = [string]$_.ProviderId
                        LogName = $_.LogName
                        MachineName = $_.MachineName
                        UserId = [string]$_.UserId
                        RecordId = $_.RecordId
                        Task = $_.Task
                        TaskDisplayName = $_.TaskDisplayName
                        Opcode = $_.Opcode
                        OpcodeDisplayName = $_.OpcodeDisplayName
                        Keywords = $_.Keywords
                        KeywordsDisplayNames = @($_.KeywordsDisplayNames)
                        ProcessId = $_.ProcessId
                        ThreadId = $_.ThreadId
                        ActivityId = [string]$_.ActivityId
                        RelatedActivityId = [string]$_.RelatedActivityId
                        PayloadValues = @($_.Properties | ForEach-Object { $_.Value })
                        Message = $message
                    }
                })
            }
            catch {
                if ($_.Exception.Message -notmatch 'No events were found|NoMatchingEventsFound') {
                    $queryError = $_.Exception.Message
                    Add-ICCollectorWarning -List $warnings -Message "Event query '$logName': $queryError"
                }
            }
            finally {
                $queryStopwatch.Stop()
                $queryMilliseconds = [math]::Round($queryStopwatch.Elapsed.TotalMilliseconds, 0)
            }
        }

        $summaryFiles = Export-ICCollectorData -Context $Context -Collector EventLogs -RelativePath $summaryJsonRelative -Data $events
        Add-ICOutputFiles -List $files -Path $summaryFiles
        $csvPath = Join-Path $Context.RootPath ($summaryCsvRelative -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        $csvRows = @($events | ForEach-Object {
            [pscustomobject][ordered]@{
                TimeCreatedUtc = $_.TimeCreatedUtc
                Id = $_.Id
                LevelDisplayName = $_.LevelDisplayName
                ProviderName = $_.ProviderName
                MachineName = $_.MachineName
                UserId = $_.UserId
                RecordId = $_.RecordId
                ProcessId = $_.ProcessId
                ThreadId = $_.ThreadId
                TaskDisplayName = $_.TaskDisplayName
                OpcodeDisplayName = $_.OpcodeDisplayName
                Keywords = ($_.KeywordsDisplayNames -join ';')
                Message = ([string]$_.Message -replace "`r?`n", ' ')
            }
        })
        [void](Write-ICCsvFile -Path $csvPath -InputObject $csvRows -SpreadsheetSafe ([bool]$Context.Configuration.SpreadsheetSafeCsv))
        [void]$files.Add($csvPath)
        $eventTotal += $events.Count

        if ($available -and $Context.Configuration.ExportEvtx) {
            $evtxStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $evtxRelative = "evidence/events/evtx/$fileBase.evtx"
            $evtxPath = Join-Path $Context.RootPath ($evtxRelative -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            $evtxDirectory = Split-Path -Parent $evtxPath
            if (-not (Test-Path -LiteralPath $evtxDirectory)) { New-Item -ItemType Directory -Path $evtxDirectory -Force | Out-Null }
            $query = "*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
            $export = Invoke-ICNativeCommand -FilePath $wevtutilPath -ArgumentList @('epl', $logName, $evtxPath, '/ow:true', "/q:$query") -Context $Context
            if ($null -eq $export.Error -and $export.ExitCode -eq 0 -and (Test-Path -LiteralPath $evtxPath -PathType Leaf)) {
                $maximumEvtxBytes = [int64](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'MaximumEvtxBytesPerLog' -Default 268435456L)
                $evtxLength = [int64](Get-Item -LiteralPath $evtxPath -Force).Length
                if ($evtxLength -gt $maximumEvtxBytes) {
                    Remove-Item -LiteralPath $evtxPath -Force -ErrorAction SilentlyContinue
                    $evtxRelative = $null
                    $exportError = "EVTX export exceeded the $maximumEvtxBytes-byte per-channel limit and was removed."
                    Add-ICCollectorWarning -List $warnings -Message "EVTX export '$logName' reached a configured limit: $exportError"
                }
                else {
                    [void]$files.Add($evtxPath)
                    $evtxCount++
                }
            }
            else {
                $exportError = if ($null -ne $export.Error) { $export.Error } else { @($export.Output) -join ' | ' }
                Add-ICCollectorWarning -List $warnings -Message "EVTX export '$logName': $exportError"
            }
            $evtxStopwatch.Stop()
            $evtxExportMilliseconds = [math]::Round($evtxStopwatch.Elapsed.TotalMilliseconds, 0)
        }

        [void]$channelRecords.Add([pscustomobject][ordered]@{
            LogName = $logName
            Available = $available
            IsEnabled = if ($null -ne $logInfo) { $logInfo.IsEnabled } else { $null }
            RecordCount = if ($null -ne $logInfo) { $logInfo.RecordCount } else { $null }
            LogMode = if ($null -ne $logInfo) { [string]$logInfo.LogMode } else { $null }
            MaximumSizeInBytes = if ($null -ne $logInfo) { $logInfo.MaximumSizeInBytes } else { $null }
            FileSize = if ($null -ne $logInfo) { $logInfo.FileSize } else { $null }
            LogFilePath = if ($null -ne $logInfo) { $logInfo.LogFilePath } else { $null }
            EventsExported = $events.Count
            EventLimit = $Context.Configuration.MaximumEventsPerLog
            LookbackHours = $Context.Configuration.EventLookbackHours
            SummaryJson = $summaryJsonRelative
            SummaryCsv = $summaryCsvRelative
            Evtx = $evtxRelative
            QueryError = $queryError
            ExportError = $exportError
            QueryMilliseconds = $queryMilliseconds
            EvtxExportMilliseconds = $evtxExportMilliseconds
            TotalMilliseconds = [math]::Round($channelStopwatch.Elapsed.TotalMilliseconds, 0)
        })
    }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector EventLogs -RelativePath 'evidence/events/channels.json' -Data @($channelRecords) -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        ConfiguredChannels = @($Context.Configuration.EventLogs).Count
        AvailableChannels = $availableCount
        DecodedEvents = $eventTotal
        EvtxFiles = $evtxCount
        LookbackHours = $Context.Configuration.EventLookbackHours
        MaximumEventsPerLog = $Context.Configuration.MaximumEventsPerLog
    })
}

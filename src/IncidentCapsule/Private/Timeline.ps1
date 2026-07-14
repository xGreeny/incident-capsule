function Get-ICTimelineTitle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Record,

        [Parameter(Mandatory)]
        [string]$TimestampProperty
    )

    foreach ($name in @('Message', 'ThreatName', 'Name', 'TaskName', 'ProcessName', 'DisplayName', 'Title')) {
        $value = Get-ICPropertyValue -InputObject $Record -Name $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            $text = ([string]$value -replace "`r?`n", ' ').Trim()
            if ($text.Length -gt 240) {
                return $text.Substring(0, 237) + '...'
            }
            return $text
        }
    }

    return $TimestampProperty
}

function ConvertTo-ICTimelineIdentifier {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or $Value -is [string]) {
        return $Value
    }

    if (
        $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
    ) {
        return $Value
    }

    return [string]$Value
}

function ConvertTo-ICTimelineEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Record,

        [Parameter(Mandatory)]
        [string]$TimestampProperty,

        [Parameter(Mandatory)]
        [string]$Collector,

        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [ValidateRange(0, 2147483647)]
        [int]$SourceIndex
    )

    $rawTimestamp = Get-ICPropertyValue -InputObject $Record -Name $TimestampProperty
    if ([string]::IsNullOrWhiteSpace([string]$rawTimestamp)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetimeoffset]::TryParse(
        [string]$rawTimestamp,
        [System.Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$parsed
    )) {
        return $null
    }

    $recordId = Get-ICPropertyValue -InputObject $Record -Name 'RecordId'
    if ($null -eq $recordId) {
        $recordId = Get-ICPropertyValue -InputObject $Record -Name 'DetectionID'
    }
    if ($null -eq $recordId) {
        $recordId = Get-ICPropertyValue -InputObject $Record -Name 'ProcessId'
    }

    $eventId = Get-ICPropertyValue -InputObject $Record -Name 'Id'
    $providerValue = Get-ICPropertyValue -InputObject $Record -Name 'ProviderName'
    $provider = if ($null -ne $providerValue) { [string]$providerValue } else { $null }
    return [pscustomobject][ordered]@{
        timestampUtc = $parsed.UtcDateTime.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        collector    = $Collector
        eventType    = $TimestampProperty
        title        = Get-ICTimelineTitle -Record $Record -TimestampProperty $TimestampProperty
        source       = $SourcePath
        sourceIndex  = $SourceIndex
        recordId     = ConvertTo-ICTimelineIdentifier -Value $recordId
        eventId      = ConvertTo-ICTimelineIdentifier -Value $eventId
        provider     = $provider
    }
}

function Select-ICNewestTimelineEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Entries,

        [Parameter(Mandatory)]
        [ValidateRange(1, 5000000)]
        [int]$MaximumEntries
    )

    return @(
        $Entries |
            Sort-Object -Property `
                @{ Expression = { [string]$_.timestampUtc }; Descending = $true },
                @{ Expression = { [string]$_.source }; Ascending = $true },
                @{ Expression = { [string]$_.collector }; Ascending = $true },
                @{ Expression = { [string]$_.eventType }; Ascending = $true },
                @{ Expression = { [int]$_.sourceIndex }; Ascending = $true },
                @{ Expression = { [string]$_.recordId }; Ascending = $true } |
            Select-Object -First $MaximumEntries
    )
}

function Limit-ICTimelineBuffer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Buffer,

        [Parameter(Mandatory)]
        [ValidateRange(1, 5000000)]
        [int]$MaximumEntries
    )

    if ($Buffer.Count -le $MaximumEntries) {
        return
    }

    $selected = @(Select-ICNewestTimelineEntry -Entries @($Buffer) -MaximumEntries $MaximumEntries)
    [void]$Buffer.Clear()
    foreach ($entry in $selected) {
        [void]$Buffer.Add($entry)
    }
}

function Get-ICTimelineEntriesFromEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$CapsuleRoot,

        [ValidateRange(1, 5000000)]
        [int]$MaximumEntries = 2000
    )

    try {
        $relativePath = Get-ICRelativePath -BasePath $CapsuleRoot -Path $Path
        $envelope = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [pscustomobject][ordered]@{
            ReadSucceeded        = $false
            CandidateCount       = 0L
            InvalidTimestampCount = 0L
            Entries              = @()
        }
    }

    $collector = [string](Get-ICPropertyValue -InputObject $envelope -Name 'collector' -Default 'Unknown')
    if ([string]::IsNullOrWhiteSpace($collector)) {
        $collector = 'Unknown'
    }
    $data = Get-ICPropertyValue -InputObject $envelope -Name 'data'
    if ($null -eq $data) {
        return [pscustomobject][ordered]@{
            ReadSucceeded        = $true
            CandidateCount       = 0L
            InvalidTimestampCount = 0L
            Entries              = @()
        }
    }

    $timestampProperties = @(
        'TimeCreatedUtc',
        'CreationDateUtc',
        'CreationTimeUtc',
        'InitialDetectionTimeUtc',
        'LastThreatStatusChangeTimeUtc',
        'RemediationTimeUtc',
        'LastRunTimeUtc',
        'NextRunTimeUtc',
        'InstallDateUtc',
        'DateUtc',
        'DriverDateUtc',
        'LastBootUpTimeUtc',
        'BootTimeUtc',
        'StartTimeUtc',
        'LastUseTimeUtc',
        'LastLogonUtc',
        'PasswordLastSetUtc',
        'PasswordExpiresUtc',
        'AccountExpiresUtc',
        'AntivirusSignatureLastUpdatedUtc',
        'AntispywareSignatureLastUpdatedUtc',
        'NISSignatureLastUpdatedUtc',
        'QuickScanEndTimeUtc',
        'FullScanEndTimeUtc',
        'CapturedAtUtc'
    )

    $entries = New-Object System.Collections.ArrayList
    $candidateCount = 0L
    $invalidTimestampCount = 0L
    $pruneThreshold = $MaximumEntries + [math]::Min($MaximumEntries, 1024)
    $sourceIndex = -1
    foreach ($record in @($data)) {
        $sourceIndex++
        if ($null -eq $record) {
            continue
        }
        foreach ($propertyName in $timestampProperties) {
            if ($null -eq $record.PSObject.Properties[$propertyName]) {
                continue
            }
            $entry = ConvertTo-ICTimelineEntry `
                -Record $record `
                -TimestampProperty $propertyName `
                -Collector $collector `
                -SourcePath $relativePath `
                -SourceIndex $sourceIndex
            if ($null -eq $entry) {
                $invalidTimestampCount++
                continue
            }

            $candidateCount++
            [void]$entries.Add($entry)
            if ($entries.Count -ge $pruneThreshold) {
                Limit-ICTimelineBuffer -Buffer $entries -MaximumEntries $MaximumEntries
            }
        }
    }
    Limit-ICTimelineBuffer -Buffer $entries -MaximumEntries $MaximumEntries

    return [pscustomobject][ordered]@{
        ReadSucceeded         = $true
        CandidateCount        = $candidateCount
        InvalidTimestampCount = $invalidTimestampCount
        Entries               = @($entries)
    }
}

function New-ICTimelineIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $configuration = Get-ICPropertyValue -InputObject $Context -Name 'Configuration'
    $maximumEntries = [int](Get-ICPropertyValue -InputObject $configuration -Name 'MaximumTimelineEntries' -Default 2000)
    if ($maximumEntries -lt 1 -or $maximumEntries -gt 5000000) {
        $maximumEntries = 2000
    }

    $candidates = New-Object System.Collections.ArrayList
    $jsonFiles = @(
        Get-ChildItem -LiteralPath $Context.EvidencePath -Filter '*.json' -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object FullName
    )
    $totalCandidates = 0L
    $invalidTimestampCount = 0L
    $sourceFilesRead = 0
    $sourceFilesFailed = 0
    $pruneThreshold = $maximumEntries + [math]::Min($maximumEntries, 1024)
    foreach ($file in $jsonFiles) {
        $fileResult = Get-ICTimelineEntriesFromEnvelope `
            -Path $file.FullName `
            -CapsuleRoot $Context.RootPath `
            -MaximumEntries $maximumEntries
        if (-not $fileResult.ReadSucceeded) {
            $sourceFilesFailed++
            continue
        }

        $sourceFilesRead++
        $totalCandidates += [int64]$fileResult.CandidateCount
        $invalidTimestampCount += [int64]$fileResult.InvalidTimestampCount
        foreach ($entry in @($fileResult.Entries)) {
            [void]$candidates.Add($entry)
            if ($candidates.Count -ge $pruneThreshold) {
                Limit-ICTimelineBuffer -Buffer $candidates -MaximumEntries $maximumEntries
            }
        }
    }
    Limit-ICTimelineBuffer -Buffer $candidates -MaximumEntries $maximumEntries

    $selected = @(
        $candidates |
            Sort-Object -Property `
                @{ Expression = { [string]$_.timestampUtc }; Ascending = $true },
                @{ Expression = { [string]$_.source }; Ascending = $true },
                @{ Expression = { [string]$_.collector }; Ascending = $true },
                @{ Expression = { [string]$_.eventType }; Ascending = $true },
                @{ Expression = { [int]$_.sourceIndex }; Ascending = $true },
                @{ Expression = { [string]$_.recordId }; Ascending = $true }
    )
    $truncated = $totalCandidates -gt $selected.Count

    $analysisDirectory = Join-Path $Context.RootPath 'analysis'
    if (-not (Test-Path -LiteralPath $analysisDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $analysisDirectory -Force | Out-Null
    }

    $jsonPath = Join-Path $analysisDirectory 'timeline.json'
    $csvPath = Join-Path $analysisDirectory 'timeline.csv'
    $timeline = [ordered]@{
        '$schema'             = $script:ICTimelineSchema
        schemaVersion         = $script:ICSchemaVersion
        capsuleId             = $Context.CapsuleId
        generatedAtUtc        = [datetime]::UtcNow.ToString('o')
        sourceFiles           = $jsonFiles.Count
        sourceFilesRead       = $sourceFilesRead
        sourceFilesFailed     = $sourceFilesFailed
        candidateCount        = $totalCandidates
        invalidTimestampCount = $invalidTimestampCount
        entryCount            = $selected.Count
        maximumEntries        = $maximumEntries
        truncated             = $truncated
        entries               = @($selected)
    }

    [void](Write-ICJsonFile -Path $jsonPath -InputObject $timeline -Depth 12)
    [void](Write-ICCsvFile -Path $csvPath -InputObject $selected -SpreadsheetSafe ([bool](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'SpreadsheetSafeCsv' -Default $true)))

    $result = [pscustomobject][ordered]@{
        JsonPath              = $jsonPath
        CsvPath               = $csvPath
        SourceFiles           = $jsonFiles.Count
        SourceFilesRead       = $sourceFilesRead
        SourceFilesFailed     = $sourceFilesFailed
        CandidateCount        = $totalCandidates
        InvalidTimestampCount = $invalidTimestampCount
        EntryCount            = $selected.Count
        MaximumEntries        = $maximumEntries
        Truncated             = $truncated
        Entries               = @($selected)
    }
    $Context | Add-Member -NotePropertyName Timeline -NotePropertyValue $result -Force
    return $result
}

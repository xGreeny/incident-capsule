function New-ICStructuredIssue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z][A-Z0-9_]+$')]
        [string]$Code,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Component,

        [Parameter(Mandatory)]
        [string]$Message,

        [AllowNull()]
        [string]$Source,

        [AllowNull()]
        [System.Collections.IDictionary]$Details
    )

    return [pscustomobject][ordered]@{
        code      = $Code
        severity  = $Severity
        component = $Component
        message   = $Message
        source    = $Source
        details   = if ($null -ne $Details) { $Details } else { [ordered]@{} }
    }
}

function ConvertTo-ICStructuredIssue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Component,

        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Warning', 'Error')]
        [string]$Kind = 'Warning',

        [AllowNull()]
        [string]$Source
    )

    $code = 'SOURCE_WARNING'
    $severity = if ($Kind -eq 'Error') { 'Error' } else { 'Warning' }

    switch -Regex ($Message) {
        '(?i)access.+denied|denied.+access|privilege|requires? elevation|not elevated' {
            $code = 'ACCESS_DENIED'
            break
        }
        '(?i)event channel.+unavailable|event log.+unavailable|channel.+not found' {
            $code = 'CHANNEL_UNAVAILABLE'
            break
        }
        '(?i)cmdlets? (are|is) unavailable|command.+not found|executable.+not found' {
            $code = 'COMMAND_UNAVAILABLE'
            break
        }
        '(?i)timed? out|timeout' {
            $code = 'TIMEOUT'
            break
        }
        '(?i)bounded|truncat|limit.+reached|maximum.+reached' {
            $code = 'LIMIT_REACHED'
            break
        }
        '(?i)insufficient.+space|not enough.+space|disk.+full' {
            $code = 'INSUFFICIENT_SPACE'
            break
        }
        '(?i)unavailable|does not exist|not available|missing' {
            $code = 'SOURCE_UNAVAILABLE'
            break
        }
        '(?i)failed|failure|fatal|error' {
            $code = 'COLLECTION_ERROR'
            break
        }
    }

    return New-ICStructuredIssue `
        -Code $code `
        -Severity $severity `
        -Component $Component `
        -Message $Message `
        -Source $Source
}

function Get-ICCollectorIssue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $issues = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($result in @($CollectorResults)) {
        $component = [string](Get-ICPropertyValue -InputObject $result -Name 'name' -Default 'Unknown')
        if ([string]::IsNullOrWhiteSpace($component)) {
            $component = 'Unknown'
        }

        foreach ($existingIssue in @(Get-ICPropertyValue -InputObject $result -Name 'issues' -Default @())) {
            if ($null -eq $existingIssue) {
                continue
            }

            $message = if ($existingIssue -is [string]) {
                [string]$existingIssue
            }
            else {
                [string](Get-ICPropertyValue -InputObject $existingIssue -Name 'message')
            }
            if ([string]::IsNullOrWhiteSpace($message)) {
                continue
            }

            $issueComponent = [string](Get-ICPropertyValue -InputObject $existingIssue -Name 'component' -Default $component)
            if ([string]::IsNullOrWhiteSpace($issueComponent)) {
                $issueComponent = $component
            }

            $severity = [string](Get-ICPropertyValue -InputObject $existingIssue -Name 'severity' -Default 'Warning')
            if ($severity -notin @('Info', 'Warning', 'Error')) {
                $severity = 'Warning'
            }

            $code = [string](Get-ICPropertyValue -InputObject $existingIssue -Name 'code')
            if ($code -notmatch '^[A-Z][A-Z0-9_]+$') {
                $code = if ($severity -eq 'Error') { 'COLLECTION_ERROR' } else { 'SOURCE_WARNING' }
            }

            $sourceValue = Get-ICPropertyValue -InputObject $existingIssue -Name 'source'
            $source = if ($null -ne $sourceValue) { [string]$sourceValue } else { $null }
            $detailsValue = Get-ICPropertyValue -InputObject $existingIssue -Name 'details'
            $details = if ($detailsValue -is [System.Collections.IDictionary]) { $detailsValue } else { [ordered]@{} }
            $normalized = New-ICStructuredIssue `
                -Code $code `
                -Severity $severity `
                -Component $issueComponent `
                -Message $message `
                -Source $source `
                -Details $details
            $identity = '{0}|{1}|{2}|{3}' -f $normalized.code, $normalized.severity, $normalized.component, $normalized.message
            if ($seen.Add($identity)) {
                [void]$issues.Add($normalized)
            }
        }

        foreach ($warning in @(Get-ICPropertyValue -InputObject $result -Name 'warnings' -Default @())) {
            if (-not [string]::IsNullOrWhiteSpace([string]$warning)) {
                $normalized = ConvertTo-ICStructuredIssue -Component $component -Message ([string]$warning)
                $identity = '{0}|{1}|{2}|{3}' -f $normalized.code, $normalized.severity, $normalized.component, $normalized.message
                if ($seen.Add($identity)) {
                    [void]$issues.Add($normalized)
                }
            }
        }

        $errorMessage = [string](Get-ICPropertyValue -InputObject $result -Name 'error')
        if (-not [string]::IsNullOrWhiteSpace($errorMessage)) {
            $normalized = ConvertTo-ICStructuredIssue -Component $component -Message $errorMessage -Kind Error
            $identity = '{0}|{1}|{2}|{3}' -f $normalized.code, $normalized.severity, $normalized.component, $normalized.message
            if ($seen.Add($identity)) {
                [void]$issues.Add($normalized)
            }
        }
    }

    return @($issues)
}

function Get-ICPrivacyScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $dataHandlingProfile = Get-ICPropertyValue -InputObject $Configuration -Name 'DataHandlingProfile' -Default 'Full'
    return [ordered]@{
        dataHandlingProfile             = [string]$dataHandlingProfile
        processCommandLines             = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'IncludeProcessCommandLines' -Default $false)
        nativeEventLogs                 = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'ExportEvtx' -Default $false)
        scheduledTaskXml                = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'ExportScheduledTaskXml' -Default $false)
        defenderPreferences             = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'CollectDefenderPreferences' -Default $false)
        windowsUpdateHistory            = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'CollectWindowsUpdateHistory' -Default $false)
        signedDriverInventory           = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'CollectSignedDrivers' -Default $false)
        runningExecutableHashes         = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'HashProcessExecutables' -Default $false)
        persistenceFileHashes           = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'HashPersistenceFiles' -Default $false)
        spreadsheetSafeCsv              = [bool](Get-ICPropertyValue -InputObject $Configuration -Name 'SpreadsheetSafeCsv' -Default $true)
        containsPotentiallySensitiveData = $true
    }
}

function Get-ICResourceLimit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $keys = @(
        'EventLookbackHours',
        'MaximumEventsPerLog',
        'MaximumEvtxBytesPerLog',
        'MaximumExecutableHashes',
        'MaximumWindowsUpdateHistory',
        'MaximumSignedDrivers',
        'MaximumFirewallRules',
        'MaximumPrefetchFiles',
        'MaximumArtifactFileBytes',
        'MaximumCapsuleBytes',
        'NativeCommandTimeoutSeconds',
        'MaximumNativeOutputBytes',
        'MaximumTimelineEntries',
        'MaximumArchiveEntries',
        'MaximumArchiveEntryBytes',
        'MaximumArchiveExpandedBytes',
        'MaximumArchiveCompressionRatio'
    )

    $limits = [ordered]@{}
    foreach ($key in $keys) {
        $value = Get-ICPropertyValue -InputObject $Configuration -Name $key
        if ($null -ne $value) {
            $limits[$key] = $value
        }
    }
    return $limits
}

function New-ICCoverageData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $configuration = Get-ICPropertyValue -InputObject $Context -Name 'Configuration'
    if (-not ($configuration -is [System.Collections.IDictionary])) {
        throw 'Coverage generation requires a resolved configuration dictionary.'
    }

    $selectedCollectors = @(Get-ICPropertyValue -InputObject $configuration -Name 'Collectors' -Default @())
    $collectorResults = @(Get-ICPropertyValue -InputObject $Context -Name 'CollectorResults' -Default @())
    $entries = New-Object System.Collections.ArrayList

    foreach ($name in @($script:ICCollectorDefinitions.Keys)) {
        $selected = $name -in $selectedCollectors
        $result = @(
            $collectorResults |
                Where-Object { (Get-ICPropertyValue -InputObject $_ -Name 'name') -eq $name } |
                Select-Object -First 1
        )
        $resultObject = if ($result.Count -gt 0) { $result[0] } else { $null }
        $status = if (-not $selected) {
            'NotSelected'
        }
        elseif ($null -eq $resultObject) {
            'NotRun'
        }
        else {
            [string](Get-ICPropertyValue -InputObject $resultObject -Name 'status' -Default 'Failed')
        }

        if ($status -notin @('NotSelected', 'NotRun', 'Succeeded', 'Partial', 'Failed', 'Skipped')) {
            $status = 'Failed'
        }

        $entryIssues = @(
            if ($null -ne $resultObject) {
                Get-ICCollectorIssue -CollectorResults @($resultObject)
            }
        )

        $outputFileCount = 0
        if ($null -ne $resultObject) {
            $outputFileCount = @(Get-ICPropertyValue -InputObject $resultObject -Name 'outputFiles' -Default @()).Count
        }

        [void]$entries.Add([pscustomobject][ordered]@{
            name        = $name
            selected    = $selected
            status      = $status
            outputFiles = $outputFileCount
            issueCount  = $entryIssues.Count
            issues      = @($entryIssues)
        })
    }

    $allIssues = @(Get-ICCollectorIssue -CollectorResults $collectorResults)
    $summary = [ordered]@{
        totalCollectors    = @($script:ICCollectorDefinitions.Keys).Count
        selectedCollectors = @($entries | Where-Object selected -eq $true).Count
        notSelected        = @($entries | Where-Object status -eq 'NotSelected').Count
        notRun             = @($entries | Where-Object status -eq 'NotRun').Count
        succeeded          = @($entries | Where-Object status -eq 'Succeeded').Count
        partial            = @($entries | Where-Object status -eq 'Partial').Count
        failed             = @($entries | Where-Object status -eq 'Failed').Count
        skipped            = @($entries | Where-Object status -eq 'Skipped').Count
        issueCount         = $allIssues.Count
        errorCount         = @($allIssues | Where-Object severity -eq 'Error').Count
        warningCount       = @($allIssues | Where-Object severity -eq 'Warning').Count
        limitsReached      = @($allIssues | Where-Object code -eq 'LIMIT_REACHED').Count
    }

    return [ordered]@{
        '$schema'      = $script:ICCoverageSchema
        schemaVersion  = $script:ICSchemaVersion
        capsuleId      = $Context.CapsuleId
        generatedAtUtc = [datetime]::UtcNow.ToString('o')
        summary        = $summary
        privacyScope   = Get-ICPrivacyScope -Configuration $configuration
        resourceLimits = Get-ICResourceLimit -Configuration $configuration
        collectors     = @($entries)
        issues         = @($allIssues)
    }
}

function Write-ICCoverageData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $coverage = New-ICCoverageData -Context $Context
    $path = Join-Path $Context.MetadataPath 'coverage.json'
    [void](Write-ICJsonFile -Path $path -InputObject $coverage -Depth 30)
    $Context | Add-Member -NotePropertyName Coverage -NotePropertyValue $coverage -Force
    $Context | Add-Member -NotePropertyName CoveragePath -NotePropertyValue $path -Force
    return $path
}

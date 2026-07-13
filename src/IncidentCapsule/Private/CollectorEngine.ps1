function Invoke-ICCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $script:ICCollectorDefinitions.Contains($Name)) {
        throw "Collector '$Name' is not registered."
    }

    $definition = $script:ICCollectorDefinitions[$Name]
    $functionName = [string]$definition.Function
    $startedAt = [datetime]::UtcNow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-ICLog -Context $Context -Level INFO -Component $Name -Message 'Collector started.'

    $status = 'Succeeded'
    $errorMessage = $null
    $outputFiles = @()
    $warnings = @()
    $metrics = [ordered]@{}

    try {
        $collectorData = & $functionName -Context $Context
        if ($null -eq $collectorData) {
            $collectorData = New-ICCollectorResultData -Warnings @('Collector returned no result object.')
        }

        $outputFiles = @($collectorData.OutputFiles | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $warnings = @($collectorData.Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($null -ne $collectorData.Metrics) {
            $metrics = $collectorData.Metrics
        }

        if ($warnings.Count -gt 0) {
            $status = 'Partial'
            foreach ($warning in $warnings) {
                Write-ICLog -Context $Context -Level WARN -Component $Name -Message $warning
            }
        }
    }
    catch {
        $status = 'Failed'
        $errorMessage = $_.Exception.Message
        Write-ICLog -Context $Context -Level ERROR -Component $Name -Message $errorMessage
    }
    finally {
        $stopwatch.Stop()
    }

    $relativeFiles = New-Object System.Collections.ArrayList
    foreach ($file in $outputFiles) {
        try {
            [void]$relativeFiles.Add((Get-ICRelativePath -BasePath $Context.RootPath -Path $file))
        }
        catch {
            $warnings += "Collector reported an output outside the capsule root: $file"
            if ($status -eq 'Succeeded') {
                $status = 'Partial'
            }
        }
    }

    $result = [pscustomobject][ordered]@{
        name              = $Name
        description       = [string]$definition.Description
        status            = $status
        startedAtUtc      = $startedAt.ToString('o')
        completedAtUtc    = [datetime]::UtcNow.ToString('o')
        durationMilliseconds = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 0)
        outputFiles       = @($relativeFiles)
        warnings          = @($warnings)
        error             = $errorMessage
        metrics           = $metrics
    }

    [void]$Context.CollectorResults.Add($result)
    Write-ICLog -Context $Context -Level INFO -Component $Name -Message ("Collector completed with state {0}; {1} output file(s); {2} warning(s); {3} ms." -f $status, $relativeFiles.Count, $warnings.Count, $result.durationMilliseconds)
    return $result
}

function Invoke-ICCollectors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $names = @($Context.Configuration.Collectors)
    $index = 0
    foreach ($name in $names) {
        $index++
        $percent = [int](($index - 1) / [math]::Max($names.Count, 1) * 100)
        Write-Progress -Activity 'Incident Capsule' -Status "Collecting $name ($index/$($names.Count))" -PercentComplete $percent
        [void](Invoke-ICCollector -Context $Context -Name $name)
    }

    Write-Progress -Activity 'Incident Capsule' -Completed
    return @($Context.CollectorResults)
}

function Get-ICOverallStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CollectorResults,

        [AllowNull()]
        [string]$FatalError
    )

    if (-not [string]::IsNullOrWhiteSpace($FatalError)) {
        return 'Failed'
    }
    if (@($CollectorResults | Where-Object status -eq 'Failed').Count -gt 0) {
        return 'CompletedWithErrors'
    }
    if (@($CollectorResults | Where-Object status -eq 'Partial').Count -gt 0) {
        return 'CompletedWithWarnings'
    }
    return 'Completed'
}

function New-ICCapsuleMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $hostDomain = $null
    $osCaption = $null
    $osVersion = $null
    $osBuild = $null
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hostDomain = $computer.Domain
    }
    catch { }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osCaption = $os.Caption
        $osVersion = $os.Version
        $osBuild = $os.BuildNumber
    }
    catch { }

    $completed = if ($null -ne $Context.CompletedAtUtc) { $Context.CompletedAtUtc } else { [datetime]::UtcNow }
    $duration = ($completed - $Context.StartedAtUtc).TotalSeconds

    return [ordered]@{
        '$schema'     = $script:ICCapsuleSchema
        schemaVersion = $script:ICSchemaVersion
        tool = [ordered]@{
            name    = $script:ICName
            version = $script:ICVersion
            project = 'https://github.com/xGreeny/incident-capsule'
        }
        capsule = [ordered]@{
            id      = $Context.CapsuleId
            caseId  = $Context.CaseId
            profile = $Context.Profile
            status  = $Context.Status
        }
        host = [ordered]@{
            name    = $Context.HostName
            domain  = $hostDomain
            os      = $osCaption
            version = $osVersion
            build   = $osBuild
        }
        collection = [ordered]@{
            operator        = $Context.Operator
            executionUser   = Get-ICCurrentUser
            elevated        = [bool]$Context.IsElevated
            startedAtUtc    = $Context.StartedAtUtc.ToString('o')
            completedAtUtc  = $completed.ToString('o')
            durationSeconds = [math]::Round($duration, 3)
            fatalError      = $Context.FatalError
        }
        configuration = Copy-ICValue -Value $Context.Configuration
        collectors = @($Context.CollectorResults)
        integrity = [ordered]@{
            algorithm       = 'SHA-256'
            manifest        = 'metadata/manifest.json'
            checksumList    = 'metadata/manifest.sha256'
            archiveSidecar  = 'created beside the ZIP archive'
        }
    }
}

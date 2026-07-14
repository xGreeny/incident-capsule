function Test-IncidentCapsuleReadiness {
    <#
    .SYNOPSIS
    Checks whether the local host is ready to create an Incident Capsule.

    .DESCRIPTION
    Resolves the complete effective configuration and performs local, non-collecting
    checks for platform support, output-path writability, free space, elevation,
    collector commands, CIM, and selected event channels. No capsule is created.

    .PARAMETER OutputPath
    Proposed parent directory for the capsule output.

    .PARAMETER Profile
    Built-in Minimal, Standard, or Extended profile.

    .PARAMETER ConfigurationPath
    Optional PowerShell data file whose values override profile defaults.

    .PARAMETER Collectors
    Optional explicit collector list. Replaces the profile collector list.

    .PARAMETER ExcludeCollector
    Collector names removed after all other configuration is resolved.

    .PARAMETER NoCompression
    Calculates required free space without ZIP archive headroom.

    .EXAMPLE
    Test-IncidentCapsuleReadiness -OutputPath 'E:\Evidence' -Profile Standard

    .OUTPUTS
    IncidentCapsule.Readiness
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidAssignmentToAutomaticVariable',
        '',
        Justification = 'Profile is part of the established public cmdlet vocabulary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$OutputPath = (Get-Location).Path,

        [ValidateSet('Minimal', 'Standard', 'Extended')]
        [string]$Profile = 'Standard',

        [string]$ConfigurationPath,

        [ValidateSet(
            'System', 'Storage', 'Processes', 'Services', 'Network', 'Sessions',
            'LocalAccounts', 'ScheduledTasks', 'Persistence', 'Defender', 'PowerShell',
            'SecurityConfiguration', 'Hotfixes', 'Drivers', 'EventLogs'
        )]
        [string[]]$Collectors,

        [ValidateSet(
            'System', 'Storage', 'Processes', 'Services', 'Network', 'Sessions',
            'LocalAccounts', 'ScheduledTasks', 'Persistence', 'Defender', 'PowerShell',
            'SecurityConfiguration', 'Hotfixes', 'Drivers', 'EventLogs'
        )]
        [string[]]$ExcludeCollector,

        [switch]$NoCompression
    )

    $configurationParameters = @{
        Profile = $Profile
    }
    if ($PSBoundParameters.ContainsKey('ConfigurationPath')) {
        $configurationParameters.ConfigurationPath = $ConfigurationPath
    }
    if ($PSBoundParameters.ContainsKey('Collectors')) {
        $configurationParameters.Collectors = $Collectors
    }
    if ($PSBoundParameters.ContainsKey('ExcludeCollector')) {
        $configurationParameters.ExcludeCollector = $ExcludeCollector
    }

    $configuration = Resolve-ICConfiguration @configurationParameters
    $checks = New-Object System.Collections.ArrayList
    $resolvedOutputPath = $null
    $probeDirectory = $null

    $windowsHost = Test-ICWindows
    if ($windowsHost) {
        [void]$checks.Add((New-ICReadinessCheck -Code 'WINDOWS_SUPPORTED' -Category Platform -Status Passed -Severity Information -Message 'The local host is Windows.' -Details $null))
    }
    else {
        [void]$checks.Add((New-ICReadinessCheck -Code 'WINDOWS_REQUIRED' -Category Platform -Status Failed -Severity Error -Message 'Incident Capsule collection is supported only on Windows.' -Details $null))
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        [void]$checks.Add((New-ICReadinessCheck -Code 'OUTPUT_PATH_INVALID' -Category Output -Status Failed -Severity Error -Message 'OutputPath cannot be empty.' -Details $null))
    }
    else {
        try {
            $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
        }
        catch {
            [void]$checks.Add((New-ICReadinessCheck -Code 'OUTPUT_PATH_INVALID' -Category Output -Status Failed -Severity Error -Message 'OutputPath cannot be resolved to an absolute filesystem path.' -Details ([pscustomobject][ordered]@{
                Error = $_.Exception.Message
            })))
        }
    }

    if ($null -ne $resolvedOutputPath) {
        if (Test-Path -LiteralPath $resolvedOutputPath) {
            if (Test-Path -LiteralPath $resolvedOutputPath -PathType Container) {
                $probeDirectory = $resolvedOutputPath
            }
            else {
                [void]$checks.Add((New-ICReadinessCheck -Code 'OUTPUT_PATH_NOT_DIRECTORY' -Category Output -Status Failed -Severity Error -Message 'OutputPath exists but is not a directory.' -Details ([pscustomobject][ordered]@{
                    OutputPath = $resolvedOutputPath
                })))
            }
        }
        else {
            $probeResult = Get-ICOutputProbeDirectory -Path $resolvedOutputPath
            if ($null -ne $probeResult.BlockingPath) {
                [void]$checks.Add((New-ICReadinessCheck -Code 'OUTPUT_PATH_PARENT_NOT_DIRECTORY' -Category Output -Status Failed -Severity Error -Message 'An existing OutputPath parent is not a directory.' -Details ([pscustomobject][ordered]@{
                    OutputPath = $resolvedOutputPath
                    BlockingPath = $probeResult.BlockingPath
                })))
            }
            elseif ($null -eq $probeResult.Directory) {
                [void]$checks.Add((New-ICReadinessCheck -Code 'OUTPUT_PATH_PARENT_UNAVAILABLE' -Category Output -Status Failed -Severity Error -Message 'No existing parent directory could be found for OutputPath.' -Details ([pscustomobject][ordered]@{
                    OutputPath = $resolvedOutputPath
                })))
            }
            else {
                $probeDirectory = $probeResult.Directory
            }
        }
    }

    if ($null -ne $probeDirectory) {
        $writability = Test-ICOutputWritable -Path $probeDirectory
        if ($writability.IsWritable) {
            $outputCode = 'OUTPUT_PATH_WRITABLE'
            $outputMessage = 'OutputPath exists and is writable.'
            if (-not (Test-Path -LiteralPath $resolvedOutputPath)) {
                $outputCode = 'OUTPUT_PATH_CREATABLE'
                $outputMessage = 'OutputPath does not exist yet, and its nearest existing parent is writable.'
            }
            [void]$checks.Add((New-ICReadinessCheck -Code $outputCode -Category Output -Status Passed -Severity Information -Message $outputMessage -Details ([pscustomobject][ordered]@{
                OutputPath = $resolvedOutputPath
                ProbeDirectory = $probeDirectory
            })))
        }
        else {
            [void]$checks.Add((New-ICReadinessCheck -Code 'OUTPUT_PATH_NOT_WRITABLE' -Category Output -Status Failed -Severity Error -Message 'OutputPath cannot be written by the current identity.' -Details ([pscustomobject][ordered]@{
                OutputPath = $resolvedOutputPath
                ProbeDirectory = $probeDirectory
                Error = $writability.Error
            })))
        }

        $availableBytes = Get-ICAvailableStorageByte -Path $probeDirectory
        $archiveHeadroomBytes = 0L
        if (-not $NoCompression) {
            $archiveHeadroomBytes = [int64]$configuration.MaximumCapsuleBytes
        }
        $requiredBytes = [int64]$configuration.MaximumCapsuleBytes + $archiveHeadroomBytes
        $spaceDetails = [pscustomobject][ordered]@{
            AvailableBytes       = if ($null -ne $availableBytes) { [int64]$availableBytes } else { $null }
            RequiredBytes        = $requiredBytes
            CapsuleBudgetBytes   = [int64]$configuration.MaximumCapsuleBytes
            ArchiveHeadroomBytes = $archiveHeadroomBytes
            CompressionEnabled   = -not [bool]$NoCompression
        }

        if ($null -eq $availableBytes) {
            [void]$checks.Add((New-ICReadinessCheck -Code 'DISK_SPACE_UNKNOWN' -Category Storage -Status Warning -Severity Warning -Message 'Available free space could not be determined.' -Details $spaceDetails))
        }
        elseif ([int64]$availableBytes -lt $requiredBytes) {
            [void]$checks.Add((New-ICReadinessCheck -Code 'INSUFFICIENT_SPACE' -Category Storage -Status Failed -Severity Error -Message 'Available free space is below the configured capsule budget and archive headroom.' -Details $spaceDetails))
        }
        else {
            [void]$checks.Add((New-ICReadinessCheck -Code 'DISK_SPACE_SUFFICIENT' -Category Storage -Status Passed -Severity Information -Message 'Available free space covers the configured capsule budget and archive headroom.' -Details $spaceDetails))
        }
    }

    $isElevated = $false
    if ($windowsHost) {
        $isElevated = Test-ICAdministrator
        if ($isElevated) {
            [void]$checks.Add((New-ICReadinessCheck -Code 'ELEVATION_PRESENT' -Category Privileges -Status Passed -Severity Information -Message 'The current Windows identity is elevated.' -Details $null))
        }
        else {
            [void]$checks.Add((New-ICReadinessCheck -Code 'NOT_ELEVATED' -Category Privileges -Status Warning -Severity Warning -Message 'The current Windows identity is not elevated; protected sources can be partial.' -Details $null))
        }

        foreach ($check in @(Get-ICCommandReadinessCheck -Configuration $configuration)) {
            [void]$checks.Add($check)
        }
        foreach ($check in @(Get-ICCimReadinessCheck -Configuration $configuration)) {
            [void]$checks.Add($check)
        }
        foreach ($check in @(Get-ICEventLogReadinessCheck -Configuration $configuration)) {
            [void]$checks.Add($check)
        }
    }

    $failedCount = @($checks | Where-Object { $_.Status -eq 'Failed' }).Count
    $warningCount = @($checks | Where-Object { $_.Status -eq 'Warning' }).Count
    $passedCount = @($checks | Where-Object { $_.Status -eq 'Passed' }).Count
    $status = 'Ready'
    if ($failedCount -gt 0) {
        $status = 'Blocked'
    }
    elseif ($warningCount -gt 0) {
        $status = 'ReadyWithWarnings'
    }

    return [pscustomobject][ordered]@{
        PSTypeName         = 'IncidentCapsule.Readiness'
        Status             = $status
        IsReady            = $status -ne 'Blocked'
        CheckedAtUtc       = [datetime]::UtcNow
        HostName           = Get-ICHostName
        IsWindows          = [bool]$windowsHost
        IsElevated         = [bool]$isElevated
        Profile            = $Profile
        OutputPath         = $resolvedOutputPath
        CompressionEnabled = -not [bool]$NoCompression
        Configuration      = Copy-ICValue -Value $configuration
        PrivacyScope       = Get-ICPrivacyScope -Configuration $configuration
        ResourceLimits     = Get-ICResourceLimit -Configuration $configuration
        Checks             = @($checks)
        Summary            = [pscustomobject][ordered]@{
            Passed  = $passedCount
            Warnings = $warningCount
            Failed  = $failedCount
        }
    }
}

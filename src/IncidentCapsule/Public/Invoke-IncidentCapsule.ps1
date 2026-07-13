function Invoke-IncidentCapsule {
    <#
    .SYNOPSIS
    Collects a local Windows first-response evidence capsule.

    .DESCRIPTION
    Runs isolated read-only collectors, writes structured evidence and native artifacts,
    generates an offline HTML report, creates a SHA-256 manifest, and optionally creates
    a ZIP archive with a sidecar checksum.

    Collection is local only. Individual collectors can complete partially when a source
    is unavailable or the current token lacks access; those limitations are recorded.

    .PARAMETER OutputPath
    Parent directory for the capsule directory, ZIP archive, and sidecar checksum.

    .PARAMETER CaseId
    External case or incident identifier stored in metadata and the folder name.

    .PARAMETER Operator
    Operator identifier. Defaults to the current Windows identity.

    .PARAMETER Profile
    Built-in Minimal, Standard, or Extended profile.

    .PARAMETER ConfigurationPath
    Optional PowerShell data file whose values override profile defaults.

    .PARAMETER Collectors
    Optional explicit collector list. Replaces the profile collector list.

    .PARAMETER ExcludeCollector
    Collector names removed after profile, configuration, and explicit selection are resolved.

    .PARAMETER NoCompression
    Keep the evidence directory without creating a ZIP archive.

    .PARAMETER RemoveWorkingDirectory
    Remove the evidence directory after the archive and sidecar checksum are created.

    .EXAMPLE
    $result = Invoke-IncidentCapsule -OutputPath 'C:\IR\Cases' -CaseId 'IR-2026-0042' -Profile Standard
    Start-Process $result.ReportPath

    .EXAMPLE
    Invoke-IncidentCapsule -OutputPath 'E:\Evidence' -CaseId 'IR-2026-0042' -Profile Extended -RemoveWorkingDirectory

    .OUTPUTS
    IncidentCapsule.Result
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$OutputPath = (Get-Location).Path,

        [string]$CaseId = ("IR-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')),

        [string]$Operator = (Get-ICCurrentUser),

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

        [switch]$NoCompression,

        [switch]$RemoveWorkingDirectory
    )

    if (-not (Test-ICWindows)) {
        throw 'Incident Capsule can collect evidence only on Windows.'
    }
    if ($RemoveWorkingDirectory -and $NoCompression) {
        throw '-RemoveWorkingDirectory requires archive creation and cannot be combined with -NoCompression.'
    }
    if ([string]::IsNullOrWhiteSpace($CaseId)) {
        throw 'CaseId cannot be empty.'
    }
    if ([string]::IsNullOrWhiteSpace($Operator)) {
        throw 'Operator cannot be empty.'
    }

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
    $context = New-ICContext -OutputPath $OutputPath -CaseId $CaseId -Operator $Operator -Profile $Profile -Configuration $configuration
    $fatalException = $null

    try {
        Write-ICLog -Context $context -Level INFO -Component Core -Message ("Incident Capsule {0} started for case '{1}' on host '{2}' using profile '{3}'." -f $script:ICVersion, $CaseId, $context.HostName, $Profile)
        if (-not $context.IsElevated) {
            Write-ICLog -Context $context -Level WARN -Component Core -Message 'Session is not elevated; protected evidence sources can be partial.'
        }

        [void](Invoke-ICCollectors -Context $context)
    }
    catch {
        $fatalException = $_
        $context.FatalError = $_.Exception.Message
        Write-ICLog -Context $context -Level ERROR -Component Core -Message ("Fatal orchestration error: {0}" -f $_.Exception.Message)
    }
    finally {
        $context.CompletedAtUtc = [datetime]::UtcNow
        $context.Status = Get-ICOverallStatus -CollectorResults @($context.CollectorResults) -FatalError $context.FatalError

        try {
            $metadata = New-ICCapsuleMetadata -Context $context
            [void](Write-ICJsonFile -Path (Join-Path $context.MetadataPath 'capsule.json') -InputObject $metadata -Depth 30)
        }
        catch {
            if ($null -eq $fatalException) { $fatalException = $_ }
            $context.FatalError = "Metadata finalization failed: $($_.Exception.Message)"
            $context.Status = 'Failed'
            Write-ICLog -Context $context -Level ERROR -Component Core -Message $context.FatalError
        }

        try {
            [void](New-ICHtmlReport -Context $context)
        }
        catch {
            if ($null -eq $fatalException) { $fatalException = $_ }
            $context.FatalError = "Report generation failed: $($_.Exception.Message)"
            $context.Status = 'Failed'
            Write-ICLog -Context $context -Level ERROR -Component Core -Message $context.FatalError
        }

        Write-ICLog -Context $context -Level INFO -Component Core -Message ("Collection frozen with overall state {0}. Manifest generation follows; no collected file will be modified." -f $context.Status)
        $context.Frozen = $true
    }

    $manifestResult = $null
    $archiveResult = $null
    try {
        $manifestResult = New-ICManifest -CapsuleRoot $context.RootPath -CapsuleId $context.CapsuleId
        $context.ManifestPath = $manifestResult.ManifestPath
        $context.ManifestTextPath = $manifestResult.TextPath

        if (-not $NoCompression) {
            $archiveResult = New-ICArchive -CapsuleRoot $context.RootPath
            $context.ArchivePath = $archiveResult.ArchivePath
            $context.ArchiveHashPath = $archiveResult.SidecarPath
        }
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $context.Status = 'Failed'
        $context.FatalError = "Integrity or archive finalization failed: $($_.Exception.Message)"
    }

    $verification = $null
    if ($null -ne $manifestResult) {
        try {
            $verification = Test-ICDirectoryIntegrity -CapsuleRoot $context.RootPath
        }
        catch {
            if ($null -eq $fatalException) { $fatalException = $_ }
            $context.Status = 'Failed'
            $context.FatalError = "Post-collection integrity verification failed: $($_.Exception.Message)"
        }
    }

    $workingDirectory = $context.RootPath
    $reportPath = $context.ReportPath
    if ($RemoveWorkingDirectory -and $null -ne $archiveResult -and $null -ne $verification -and $verification.IsValid) {
        Remove-Item -LiteralPath $context.RootPath -Recurse -Force
        $workingDirectory = $null
        $reportPath = $null
    }

    $result = [pscustomobject][ordered]@{
        PSTypeName              = 'IncidentCapsule.Result'
        CapsuleId              = $context.CapsuleId
        CaseId                 = $context.CaseId
        HostName               = $context.HostName
        Profile                = $context.Profile
        Status                 = $context.Status
        IsElevated             = $context.IsElevated
        StartedAtUtc           = $context.StartedAtUtc
        CompletedAtUtc         = $context.CompletedAtUtc
        DurationSeconds        = [math]::Round(($context.CompletedAtUtc - $context.StartedAtUtc).TotalSeconds, 3)
        WorkingDirectory       = $workingDirectory
        ReportPath             = $reportPath
        ManifestPath           = if ($null -ne $workingDirectory) { $context.ManifestPath } else { $null }
        ArchivePath            = $context.ArchivePath
        ArchiveChecksumPath    = $context.ArchiveHashPath
        ArchiveSHA256          = if ($null -ne $archiveResult) { $archiveResult.SHA256 } else { $null }
        IntegrityValid         = if ($null -ne $verification) { $verification.IsValid } else { $false }
        CollectorResults       = @($context.CollectorResults)
        FatalError             = $context.FatalError
    }

    if ($null -ne $fatalException) {
        $exception = New-Object System.InvalidOperationException(
            "Incident Capsule completed with a fatal error. Partial output: '$($context.RootPath)'. $($context.FatalError)",
            $fatalException.Exception
        )
        $exception.Data['IncidentCapsuleResult'] = $result
        throw $exception
    }

    return $result
}

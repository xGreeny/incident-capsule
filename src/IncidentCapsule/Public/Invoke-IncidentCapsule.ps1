function Invoke-IncidentCapsule {
    <#
    .SYNOPSIS
    Collects a local Windows first-response evidence capsule.

    .DESCRIPTION
    Runs isolated read-only collectors, writes structured evidence and native artifacts,
    generates an offline HTML report, creates a SHA-256 manifest, and optionally creates
    and verifies a ZIP archive with a sidecar checksum and external verification receipt.

    Collection is local only. Individual collectors can complete partially when a source
    is unavailable or the current token lacks access; those limitations are recorded.

    .PARAMETER OutputPath
    Parent directory for the capsule directory, ZIP archive, sidecar checksum, and receipt.

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
    Remove the evidence directory only after the newly created archive has passed a full
    archive hash, safe extraction, checksum-list, and embedded-manifest verification.

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

    $configurationParameters = @{ Profile = $Profile }
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
    $finalizationFailed = $false

    try {
        Write-ICLog -Context $context -Level INFO -Component Core -Message ("Incident Capsule {0} started for case '{1}' on host '{2}' using profile '{3}'." -f $script:ICVersion, $CaseId, $context.HostName, $Profile)
        if (-not $context.IsElevated) {
            Write-ICLog -Context $context -Level WARN -Component Core -Message 'Session is not elevated; protected evidence sources can be partial.'
        }

        [void](Invoke-ICCollectors -Context $context)
    }
    catch {
        $fatalException = $_
        $context.FatalError = "Collection orchestration failed: $($_.Exception.Message)"
        try { Write-ICLog -Context $context -Level ERROR -Component Core -Message $context.FatalError } catch { $null = $_ }
    }

    $context.CompletedAtUtc = [datetime]::UtcNow
    $context.CollectionStatus = Get-ICOverallStatus -CollectorResults @($context.CollectorResults) -FatalError $context.FatalError
    $context.Status = $context.CollectionStatus
    $context.FinalizationStatus = 'Preparing'

    try {
        [void](New-ICTimelineIndex -Context $context)
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Timeline finalization failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $finalizationFailed = $true
        try { Write-ICLog -Context $context -Level ERROR -Component Core -Message $message } catch { $null = $_ }
    }

    try {
        [void](Write-ICCoverageData -Context $context)
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Coverage finalization failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $finalizationFailed = $true
        try { Write-ICLog -Context $context -Level ERROR -Component Core -Message $message } catch { $null = $_ }
    }

    try {
        [void](New-ICHtmlReport -Context $context)
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Report generation failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $finalizationFailed = $true
        try { Write-ICLog -Context $context -Level ERROR -Component Core -Message $message } catch { $null = $_ }
    }

    try {
        $budgetState = Get-ICCapsuleBudgetState -Context $context
        if (-not $budgetState.IsWithinBudget) {
            throw (New-Object System.IO.InvalidDataException(
                "Capsule size $($budgetState.CurrentBytes) bytes exceeds the configured MaximumCapsuleBytes limit of $($budgetState.MaximumBytes) bytes."
            ))
        }
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Capsule resource-budget finalization failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $finalizationFailed = $true
        try { Write-ICLog -Context $context -Level ERROR -Component Core -Message $message } catch { $null = $_ }
    }

    $context.FinalizationStatus = if ($finalizationFailed) { 'Failed' } else { 'Sealing' }
    try {
        $metadata = New-ICCapsuleMetadata -Context $context
        [void](Write-ICJsonFile -Path (Join-Path $context.MetadataPath 'capsule.json') -InputObject $metadata -Depth 30)
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Metadata finalization failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $context.FinalizationStatus = 'Failed'
        $finalizationFailed = $true
        try { Write-ICLog -Context $context -Level ERROR -Component Core -Message $message } catch { $null = $_ }
    }

    try {
        Write-ICLog -Context $context -Level INFO -Component Core -Message ("Collection frozen with acquisition state {0}. Manifest generation follows; no collected file will be modified." -f $context.CollectionStatus)
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Final collection log write failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $context.FinalizationStatus = 'Failed'
        $finalizationFailed = $true
    }
    $context.Frozen = $true

    $manifestResult = $null
    $archiveResult = $null
    $verification = $null
    $archiveVerification = $null
    $verificationReceiptPath = $null
    try {
        $manifestResult = New-ICManifest -CapsuleRoot $context.RootPath -CapsuleId $context.CapsuleId
        $context.ManifestPath = $manifestResult.ManifestPath
        $context.ManifestTextPath = $manifestResult.TextPath
        $sealedBudgetState = Get-ICCapsuleBudgetState -Context $context
        if (-not $sealedBudgetState.IsWithinBudget) {
            throw (New-Object System.IO.InvalidDataException(
                "Sealed capsule size $($sealedBudgetState.CurrentBytes) bytes exceeds the configured MaximumCapsuleBytes limit of $($sealedBudgetState.MaximumBytes) bytes."
            ))
        }
        if (-not $finalizationFailed) { $context.FinalizationStatus = 'ManifestCreated' }
    }
    catch {
        if ($null -eq $fatalException) { $fatalException = $_ }
        $message = "Manifest finalization failed: $($_.Exception.Message)"
        $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
        $context.Status = 'Failed'
        $context.FinalizationStatus = 'Failed'
        $finalizationFailed = $true
    }

    if ($null -ne $manifestResult) {
        try {
            $verification = Test-ICDirectoryIntegrity -CapsuleRoot $context.RootPath
            if (-not $verification.IsValid) {
                throw (New-Object System.IO.InvalidDataException(
                    "Directory manifest verification failed: $($verification.FilesMissing) missing, $($verification.FilesModified) modified, and $($verification.FilesUnexpected) unexpected file(s)."
                ))
            }
            if (-not $finalizationFailed) { $context.FinalizationStatus = 'DirectoryVerified' }
        }
        catch {
            if ($null -eq $fatalException) { $fatalException = $_ }
            $message = "Post-collection integrity verification failed: $($_.Exception.Message)"
            $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
            $context.Status = 'Failed'
            $context.FinalizationStatus = 'Failed'
            $finalizationFailed = $true
        }
    }

    if (-not $NoCompression -and $null -ne $verification -and $verification.IsValid) {
        try {
            $archiveResult = New-ICArchive -CapsuleRoot $context.RootPath
            $context.ArchivePath = $archiveResult.ArchivePath
            $context.ArchiveHashPath = $archiveResult.SidecarPath
            if (-not $finalizationFailed) { $context.FinalizationStatus = 'Archived' }

            $archiveVerification = Test-IncidentCapsuleIntegrity `
                -Path $archiveResult.ArchivePath `
                -RequireSidecar `
                -MaximumArchiveEntries ([int]$configuration.MaximumArchiveEntries) `
                -MaximumArchiveEntryBytes ([int64]$configuration.MaximumArchiveEntryBytes) `
                -MaximumArchiveExpandedBytes ([int64]$configuration.MaximumArchiveExpandedBytes) `
                -MaximumArchiveCompressionRatio ([double]$configuration.MaximumArchiveCompressionRatio)
            $verificationReceiptPath = Write-ICVerificationReceipt -ArchivePath $archiveResult.ArchivePath -Verification $archiveVerification
            if (-not $archiveVerification.IsValid -or $archiveVerification.ArchiveHashValid -ne $true) {
                throw (New-Object System.IO.InvalidDataException('Archive verification did not validate both the sidecar checksum and the embedded manifest.'))
            }
        }
        catch {
            if ($null -eq $fatalException) { $fatalException = $_ }
            $message = "Archive finalization or verification failed: $($_.Exception.Message)"
            $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
            $context.Status = 'Failed'
            $context.FinalizationStatus = 'Failed'
            $finalizationFailed = $true
        }
    }

    $integrityValid = $null -ne $verification -and [bool]$verification.IsValid
    if (-not $NoCompression) {
        $integrityValid = $integrityValid -and $null -ne $archiveVerification -and [bool]$archiveVerification.IsValid -and $archiveVerification.ArchiveHashValid -eq $true
    }
    if (-not $finalizationFailed -and $integrityValid) {
        $context.FinalizationStatus = 'Verified'
    }
    elseif ($finalizationFailed -or -not $integrityValid) {
        $context.FinalizationStatus = 'Failed'
    }

    if ($null -ne $fatalException) {
        $context.Status = 'Failed'
    }
    else {
        $context.Status = $context.CollectionStatus
    }

    $workingDirectory = $context.RootPath
    $reportPath = $context.ReportPath
    if ($RemoveWorkingDirectory -and $null -eq $fatalException -and $context.FinalizationStatus -eq 'Verified' -and $integrityValid) {
        try {
            $outputRoot = [System.IO.Path]::GetFullPath($context.OutputPath).TrimEnd([char]'\', [char]'/')
            $deletionTarget = [System.IO.Path]::GetFullPath($context.RootPath).TrimEnd([char]'\', [char]'/')
            $outputPrefix = $outputRoot + [System.IO.Path]::DirectorySeparatorChar
            if ($deletionTarget -eq $outputRoot -or -not $deletionTarget.StartsWith($outputPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove working directory '$deletionTarget' because it is outside output root '$outputRoot'."
            }
            Remove-Item -LiteralPath $context.RootPath -Recurse -Force -ErrorAction Stop
            $workingDirectory = $null
            $reportPath = $null
        }
        catch {
            if ($null -eq $fatalException) { $fatalException = $_ }
            $message = "Verified archive was retained, but working-directory removal failed: $($_.Exception.Message)"
            $context.FatalError = if ([string]::IsNullOrWhiteSpace($context.FatalError)) { $message } else { "$($context.FatalError) | $message" }
            $context.Status = 'Failed'
            $context.FinalizationStatus = 'CleanupFailed'
            if (-not (Test-Path -LiteralPath $context.RootPath -PathType Container)) {
                $workingDirectory = $null
                $reportPath = $null
            }
        }
    }

    $context.CompletedAtUtc = [datetime]::UtcNow

    $result = [pscustomobject][ordered]@{
        PSTypeName              = 'IncidentCapsule.Result'
        CapsuleId              = $context.CapsuleId
        CaseId                 = $context.CaseId
        HostName               = $context.HostName
        Profile                = $context.Profile
        Status                 = $context.Status
        CollectionStatus       = $context.CollectionStatus
        FinalizationStatus     = $context.FinalizationStatus
        IsElevated             = $context.IsElevated
        StartedAtUtc           = $context.StartedAtUtc
        CompletedAtUtc         = $context.CompletedAtUtc
        DurationSeconds        = [math]::Round(($context.CompletedAtUtc - $context.StartedAtUtc).TotalSeconds, 3)
        WorkingDirectory       = $workingDirectory
        ReportPath             = $reportPath
        ManifestPath           = if ($null -ne $workingDirectory) { $context.ManifestPath } else { $null }
        ArchivePath            = $context.ArchivePath
        ArchiveChecksumPath    = $context.ArchiveHashPath
        ArchiveVerificationPath = $verificationReceiptPath
        ArchiveSHA256          = if ($null -ne $archiveResult) { $archiveResult.SHA256 } else { $null }
        IntegrityValid         = [bool]$integrityValid
        ArchiveIntegrityValid  = if ($NoCompression) { $null } else { [bool]($null -ne $archiveVerification -and $archiveVerification.IsValid -and $archiveVerification.ArchiveHashValid -eq $true) }
        CollectorResults       = @($context.CollectorResults)
        FatalError             = $context.FatalError
    }

    if ($null -ne $fatalException) {
        $partialPath = if ($null -ne $workingDirectory) { $workingDirectory } elseif ($null -ne $context.ArchivePath) { $context.ArchivePath } else { $context.RootPath }
        $exception = New-Object System.InvalidOperationException(
            "Incident Capsule completed with a fatal error. Partial output: '$partialPath'. $($context.FatalError)",
            $fatalException.Exception
        )
        $exception.Data['IncidentCapsuleResult'] = $result
        throw $exception
    }

    return $result
}

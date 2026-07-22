function Compare-IncidentCapsule {
    <#
    .SYNOPSIS
    Compares two Incident Capsule directories and reports evidence changes.

    .DESCRIPTION
    Diffs a curated set of stable evidence types (services, scheduled tasks,
    installed software, autorun registry values, local users and groups,
    certificate trust stores, and system drivers) between a baseline capsule and
    a current capsule of the same host. Each evidence type reports added,
    removed, and changed records keyed by a stable identity.

    Volatile evidence (running processes, live network endpoints, event
    summaries, the derived timeline) is intentionally excluded so the result
    surfaces persistence-, account-, and inventory-level change rather than
    normal runtime churn.

    Both inputs must be capsule directories. Verify and extract archives with
    Test-IncidentCapsuleIntegrity first. The comparison report is written outside
    both capsules so neither sealed capsule is modified.

    .PARAMETER BaselinePath
    Path to the earlier (baseline) capsule directory.

    .PARAMETER CurrentPath
    Path to the later (current) capsule directory.

    .PARAMETER DestinationPath
    Optional output file for the JSON comparison report. Defaults to
    '<current>.comparison.json' beside the current capsule. The destination must
    not already exist and must be outside both capsule directories.

    .EXAMPLE
    Compare-IncidentCapsule -BaselinePath $baseline.WorkingDirectory -CurrentPath $incident.WorkingDirectory

    .OUTPUTS
    IncidentCapsule.ComparisonResult
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$BaselinePath,

        [Parameter(Mandatory, Position = 1)]
        [string]$CurrentPath,

        [string]$DestinationPath
    )

    $baselineResolved = (Resolve-Path -LiteralPath $BaselinePath -ErrorAction Stop).Path
    $currentResolved = (Resolve-Path -LiteralPath $CurrentPath -ErrorAction Stop).Path
    foreach ($candidate in @($baselineResolved, $currentResolved)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
            throw "Path '$candidate' is not a capsule directory. Verify and extract an archive with Test-IncidentCapsuleIntegrity before comparing."
        }
    }

    $baselineRoot = Find-ICManifestRoot -Path $baselineResolved
    $currentRoot = Find-ICManifestRoot -Path $currentResolved

    $destination = if ($PSBoundParameters.ContainsKey('DestinationPath') -and -not [string]::IsNullOrWhiteSpace($DestinationPath)) {
        [System.IO.Path]::GetFullPath($DestinationPath)
    }
    else {
        "$currentRoot.comparison.json"
    }
    foreach ($root in @($baselineRoot, $currentRoot)) {
        $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
        if ($destination -eq $root -or $destination.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "DestinationPath '$destination' is inside a capsule directory; sealed capsules must not be modified."
        }
    }
    if (Test-Path -LiteralPath $destination) {
        throw "DestinationPath '$destination' already exists."
    }

    $baselineId = $null
    $currentId = $null
    try { $baselineId = [string]((Get-Content -LiteralPath (Join-Path $baselineRoot 'metadata/capsule.json') -Raw -Encoding UTF8 | ConvertFrom-Json).capsule.id) } catch { $baselineId = $null }
    try { $currentId = [string]((Get-Content -LiteralPath (Join-Path $currentRoot 'metadata/capsule.json') -Raw -Encoding UTF8 | ConvertFrom-Json).capsule.id) } catch { $currentId = $null }

    $sections = New-Object System.Collections.ArrayList
    $totalAdded = 0
    $totalRemoved = 0
    $totalChanged = 0
    foreach ($spec in Get-ICComparisonSpec) {
        $baselineData = Get-ICCapsuleEvidenceData -CapsuleRoot $baselineRoot -Source $spec.Source
        $currentData = Get-ICCapsuleEvidenceData -CapsuleRoot $currentRoot -Source $spec.Source
        if (-not $baselineData.Available -or -not $currentData.Available) {
            [void]$sections.Add([pscustomobject][ordered]@{
                key          = $spec.Key
                label        = $spec.Label
                source       = $spec.Source
                comparable   = $false
                reason       = if (-not $baselineData.Available) { 'Baseline evidence file is missing or unreadable.' } else { 'Current evidence file is missing or unreadable.' }
                baselineCount = @($baselineData.Data).Count
                currentCount  = @($currentData.Data).Count
                added        = @()
                removed      = @()
                changed      = @()
            })
            continue
        }

        $diff = Compare-ICEvidenceRecord -Baseline @($baselineData.Data) -Current @($currentData.Data) -IdentityFields $spec.Identity
        $totalAdded += @($diff.Added).Count
        $totalRemoved += @($diff.Removed).Count
        $totalChanged += @($diff.Changed).Count
        [void]$sections.Add([pscustomobject][ordered]@{
            key           = $spec.Key
            label         = $spec.Label
            source        = $spec.Source
            comparable    = $true
            identityFields = @($spec.Identity)
            baselineCount = @($baselineData.Data).Count
            currentCount  = @($currentData.Data).Count
            addedCount    = @($diff.Added).Count
            removedCount  = @($diff.Removed).Count
            changedCount  = @($diff.Changed).Count
            added         = @($diff.Added)
            removed       = @($diff.Removed)
            changed       = @($diff.Changed)
        })
    }

    $report = [ordered]@{
        '$schema'      = $script:ICComparisonSchema
        schemaVersion  = $script:ICSchemaVersion
        generatedAtUtc = [datetime]::UtcNow.ToString('o')
        tool           = [ordered]@{ name = $script:ICName; version = $script:ICVersion }
        baseline       = [ordered]@{ path = $baselineRoot; capsuleId = $baselineId }
        current        = [ordered]@{ path = $currentRoot; capsuleId = $currentId }
        summary        = [ordered]@{
            comparableSections = @($sections | Where-Object comparable -eq $true).Count
            skippedSections    = @($sections | Where-Object comparable -eq $false).Count
            totalAdded         = $totalAdded
            totalRemoved       = $totalRemoved
            totalChanged       = $totalChanged
        }
        sections       = @($sections)
    }

    $destinationDirectory = Split-Path -Parent $destination
    if (-not [string]::IsNullOrWhiteSpace($destinationDirectory) -and -not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force -ErrorAction Stop | Out-Null
    }
    [void](Write-ICJsonFile -Path $destination -InputObject $report -Depth 40)

    return [pscustomobject][ordered]@{
        PSTypeName         = 'IncidentCapsule.ComparisonResult'
        ReportPath         = $destination
        BaselinePath       = $baselineRoot
        CurrentPath        = $currentRoot
        BaselineCapsuleId  = $baselineId
        CurrentCapsuleId   = $currentId
        ComparableSections = @($sections | Where-Object comparable -eq $true).Count
        SkippedSections    = @($sections | Where-Object comparable -eq $false).Count
        TotalAdded         = $totalAdded
        TotalRemoved       = $totalRemoved
        TotalChanged       = $totalChanged
        Sections           = @($sections)
    }
}

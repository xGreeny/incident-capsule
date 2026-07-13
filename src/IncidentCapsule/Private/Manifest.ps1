function Get-ICManifestFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    $excluded = @('metadata/manifest.json', 'metadata/manifest.sha256')
    return @(
        Get-ChildItem -LiteralPath $CapsuleRoot -Recurse -File -Force |
            ForEach-Object {
                $relative = Get-ICRelativePath -BasePath $CapsuleRoot -Path $_.FullName
                if ($relative -notin $excluded) {
                    [pscustomobject]@{
                        File         = $_
                        RelativePath = $relative
                    }
                }
            } |
            Sort-Object RelativePath
    )
}

function New-ICManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot,

        [Parameter(Mandatory)]
        [string]$CapsuleId
    )

    $metadataDirectory = Join-Path $CapsuleRoot 'metadata'
    if (-not (Test-Path -LiteralPath $metadataDirectory)) {
        New-Item -ItemType Directory -Path $metadataDirectory -Force | Out-Null
    }

    $entries = New-Object System.Collections.ArrayList
    foreach ($entry in Get-ICManifestFiles -CapsuleRoot $CapsuleRoot) {
        $hash = Get-FileHash -LiteralPath $entry.File.FullName -Algorithm SHA256 -ErrorAction Stop
        [void]$entries.Add([ordered]@{
            path             = $entry.RelativePath
            length           = [int64]$entry.File.Length
            lastWriteTimeUtc = $entry.File.LastWriteTimeUtc.ToString('o')
            sha256           = $hash.Hash.ToLowerInvariant()
        })
    }

    $manifest = [ordered]@{
        '$schema'      = $script:ICManifestSchema
        schemaVersion  = $script:ICSchemaVersion
        capsuleId      = $CapsuleId
        algorithm      = 'SHA-256'
        createdAtUtc   = [datetime]::UtcNow.ToString('o')
        files          = @($entries)
    }

    $jsonPath = Join-Path $metadataDirectory 'manifest.json'
    $textPath = Join-Path $metadataDirectory 'manifest.sha256'
    [void](Write-ICJsonFile -Path $jsonPath -InputObject $manifest -Depth 8)

    $checksumLines = @($entries | ForEach-Object { '{0}  {1}' -f $_.sha256, $_.path })
    [void](Write-ICUtf8File -Path $textPath -Content (($checksumLines -join [Environment]::NewLine) + [Environment]::NewLine))

    return [pscustomobject][ordered]@{
        ManifestPath = $jsonPath
        TextPath     = $textPath
        FileCount    = $entries.Count
    }
}

function New-ICArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

    $archivePath = "$CapsuleRoot.zip"
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $CapsuleRoot,
        $archivePath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false
    )

    $hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256 -ErrorAction Stop
    $sidecarPath = "$archivePath.sha256"
    $line = '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), (Split-Path -Leaf $archivePath)
    [void](Write-ICUtf8File -Path $sidecarPath -Content ($line + [Environment]::NewLine))

    return [pscustomobject][ordered]@{
        ArchivePath = $archivePath
        SidecarPath = $sidecarPath
        SHA256      = $hash.Hash.ToLowerInvariant()
    }
}

function Find-ICManifestRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $direct = Join-Path $Path 'metadata/manifest.json'
    if (Test-Path -LiteralPath $direct -PathType Leaf) {
        return $Path
    }

    $manifests = @(Get-ChildItem -LiteralPath $Path -Filter 'manifest.json' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { (Split-Path -Leaf (Split-Path -Parent $_.FullName)) -eq 'metadata' })

    if ($manifests.Count -ne 1) {
        throw "Expected exactly one metadata/manifest.json below '$Path'; found $($manifests.Count)."
    }

    return Split-Path -Parent (Split-Path -Parent $manifests[0].FullName)
}

function Test-ICDirectoryIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    $manifestPath = Join-Path $CapsuleRoot 'metadata/manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Manifest not found at '$manifestPath'."
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.algorithm -ne 'SHA-256') {
        throw "Unsupported manifest algorithm '$($manifest.algorithm)'."
    }

    $fileResults = New-Object System.Collections.ArrayList
    $expected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in @($manifest.files)) {
        [void]$expected.Add([string]$entry.path)
        $fullPath = Join-Path $CapsuleRoot (([string]$entry.path) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            [void]$fileResults.Add([pscustomobject][ordered]@{
                Path           = [string]$entry.path
                Status         = 'Missing'
                ExpectedSHA256 = [string]$entry.sha256
                ActualSHA256   = $null
                ExpectedLength = [int64]$entry.length
                ActualLength   = $null
            })
            continue
        }

        $item = Get-Item -LiteralPath $fullPath -Force
        $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $status = if (
            $actualHash -eq ([string]$entry.sha256).ToLowerInvariant() -and
            [int64]$item.Length -eq [int64]$entry.length
        ) { 'Valid' } else { 'Modified' }

        [void]$fileResults.Add([pscustomobject][ordered]@{
            Path           = [string]$entry.path
            Status         = $status
            ExpectedSHA256 = [string]$entry.sha256
            ActualSHA256   = $actualHash
            ExpectedLength = [int64]$entry.length
            ActualLength   = [int64]$item.Length
        })
    }

    $excluded = @('metadata/manifest.json', 'metadata/manifest.sha256')
    foreach ($file in Get-ChildItem -LiteralPath $CapsuleRoot -Recurse -File -Force) {
        $relative = Get-ICRelativePath -BasePath $CapsuleRoot -Path $file.FullName
        if ($relative -in $excluded) {
            continue
        }
        if (-not $expected.Contains($relative)) {
            [void]$fileResults.Add([pscustomobject][ordered]@{
                Path           = $relative
                Status         = 'Unexpected'
                ExpectedSHA256 = $null
                ActualSHA256   = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                ExpectedLength = $null
                ActualLength   = [int64]$file.Length
            })
        }
    }

    $missing = @($fileResults | Where-Object Status -eq 'Missing').Count
    $modified = @($fileResults | Where-Object Status -eq 'Modified').Count
    $unexpected = @($fileResults | Where-Object Status -eq 'Unexpected').Count
    $valid = @($fileResults | Where-Object Status -eq 'Valid').Count

    return [pscustomobject][ordered]@{
        PSTypeName        = 'IncidentCapsule.IntegrityResult'
        Path              = $CapsuleRoot
        SourceType        = 'Directory'
        CapsuleId         = [string]$manifest.capsuleId
        Algorithm         = [string]$manifest.algorithm
        IsValid           = ($missing -eq 0 -and $modified -eq 0 -and $unexpected -eq 0)
        ArchiveHashValid  = $null
        FilesExpected     = @($manifest.files).Count
        FilesValid        = $valid
        FilesMissing      = $missing
        FilesModified     = $modified
        FilesUnexpected   = $unexpected
        FileResults       = @($fileResults)
    }
}

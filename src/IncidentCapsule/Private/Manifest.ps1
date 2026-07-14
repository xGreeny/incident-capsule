function ConvertTo-ICValidatedRelativePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativePath,

        [switch]$AllowDirectory
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath.IndexOf([char]0) -ge 0) {
        throw 'A manifest or archive path cannot be empty or contain a null character.'
    }

    $normalized = $RelativePath.Replace('\', '/')
    if ($AllowDirectory) {
        $normalized = $normalized.TrimEnd('/')
    }

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw "Path '$RelativePath' does not identify a file or directory."
    }
    if ($normalized.StartsWith('/') -or $normalized.StartsWith('//') -or $normalized -match '^[A-Za-z]:') {
        throw "Path '$RelativePath' must be relative."
    }
    if ($normalized.Contains(':')) {
        throw "Path '$RelativePath' contains an unsupported colon or alternate-data-stream separator."
    }

    $segments = @($normalized.Split('/'))
    if ($segments.Count -eq 0 -or @($segments | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
        throw "Path '$RelativePath' contains an empty, current-directory, or parent-directory segment."
    }

    return ($segments -join '/')
}

function Resolve-ICContainedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter(Mandatory)]
        [string]$RelativePath,

        [switch]$AllowDirectory
    )

    $safeRelativePath = ConvertTo-ICValidatedRelativePath -RelativePath $RelativePath -AllowDirectory:$AllowDirectory
    $baseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char]'\', [char]'/')
    $platformRelative = $safeRelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $baseFull $platformRelative))
    $prefix = $baseFull + [System.IO.Path]::DirectorySeparatorChar

    if (-not $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$RelativePath' resolves outside base path '$baseFull'."
    }

    return [pscustomobject][ordered]@{
        RelativePath = $safeRelativePath
        FullPath     = $fullPath
    }
}

function Assert-ICPathHasNoReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter(Mandatory)]
        [string]$FullPath
    )

    $baseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char]'\', [char]'/')
    $targetFull = [System.IO.Path]::GetFullPath($FullPath)
    $current = $baseFull

    $baseItem = Get-Item -LiteralPath $baseFull -Force -ErrorAction Stop
    if (($baseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Base path '$baseFull' is a reparse point."
    }

    $relative = $targetFull.Substring($baseFull.Length).TrimStart([char]'\', [char]'/')
    foreach ($segment in @($relative -split '[\\/]')) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Path '$current' is a reparse point and is not accepted as capsule evidence."
            }
        }
    }
}

function Get-ICSafeTreeFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath
    )

    $root = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
    if (($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Capsule root '$RootPath' is a reparse point."
    }

    $directories = New-Object 'System.Collections.Generic.Queue[System.IO.DirectoryInfo]'
    $directories.Enqueue([System.IO.DirectoryInfo]$root)
    $files = New-Object System.Collections.ArrayList

    while ($directories.Count -gt 0) {
        $directory = $directories.Dequeue()
        foreach ($item in $directory.EnumerateFileSystemInfos()) {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Capsule path '$($item.FullName)' is a reparse point."
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $directories.Enqueue([System.IO.DirectoryInfo]$item)
            }
            else {
                [void]$files.Add([System.IO.FileInfo]$item)
            }
        }
    }

    return @($files)
}

function Get-ICManifestFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    $excluded = @('metadata/manifest.json', 'metadata/manifest.sha256')
    return @(
        Get-ICSafeTreeFiles -RootPath $CapsuleRoot |
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
        Assert-ICPathHasNoReparsePoint -BasePath $Path -FullPath $direct
        return [System.IO.Path]::GetFullPath($Path)
    }

    $manifests = New-Object System.Collections.ArrayList
    foreach ($file in Get-ICSafeTreeFiles -RootPath $Path) {
        if ($file.Name -eq 'manifest.json' -and $file.Directory.Name -eq 'metadata') {
            [void]$manifests.Add($file)
        }
    }

    if ($manifests.Count -ne 1) {
        throw "Expected exactly one metadata/manifest.json below '$Path'; found $($manifests.Count)."
    }

    return Split-Path -Parent (Split-Path -Parent $manifests[0].FullName)
}

function Test-ICChecksumList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot,

        [Parameter(Mandatory)]
        [object[]]$ManifestEntries
    )

    $checksumPath = Join-Path $CapsuleRoot 'metadata/manifest.sha256'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        return $false
    }

    $expected = @{}
    foreach ($entry in @($ManifestEntries)) {
        $expected[[string]$entry.path] = ([string]$entry.sha256).ToLowerInvariant()
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in Get-Content -LiteralPath $checksumPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -notmatch '^([a-fA-F0-9]{64})  (.+)$') {
            return $false
        }

        $hash = $Matches[1].ToLowerInvariant()
        $path = ConvertTo-ICValidatedRelativePath -RelativePath $Matches[2]
        if (-not $seen.Add($path)) {
            return $false
        }
        if (-not $expected.ContainsKey($path) -or $expected[$path] -ne $hash) {
            return $false
        }
    }

    return ($seen.Count -eq $expected.Count)
}

function Test-ICDirectoryIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    $rootFull = [System.IO.Path]::GetFullPath($CapsuleRoot)
    $manifestPath = Join-Path $rootFull 'metadata/manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Manifest not found at '$manifestPath'."
    }

    Assert-ICPathHasNoReparsePoint -BasePath $rootFull -FullPath $manifestPath
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$manifest.schemaVersion -ne $script:ICSchemaVersion) {
        throw "Unsupported manifest schema version '$($manifest.schemaVersion)'."
    }
    if ([string]$manifest.algorithm -ne 'SHA-256') {
        throw "Unsupported manifest algorithm '$($manifest.algorithm)'."
    }
    if ([string]::IsNullOrWhiteSpace([string]$manifest.capsuleId)) {
        throw 'Manifest capsuleId is missing.'
    }

    $fileResults = New-Object System.Collections.ArrayList
    $expected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $entries = @($manifest.files)

    foreach ($entry in $entries) {
        $path = ConvertTo-ICValidatedRelativePath -RelativePath ([string]$entry.path)
        if (-not $expected.Add($path)) {
            throw "Manifest contains duplicate path '$path'."
        }
        if ([string]$entry.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
            throw "Manifest path '$path' contains an invalid SHA-256 value."
        }

        $expectedLength = [int64]$entry.length
        if ($expectedLength -lt 0) {
            throw "Manifest path '$path' contains a negative length."
        }

        $resolved = Resolve-ICContainedPath -BasePath $rootFull -RelativePath $path
        $fullPath = $resolved.FullPath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            [void]$fileResults.Add([pscustomobject][ordered]@{
                Path           = $path
                Status         = 'Missing'
                ExpectedSHA256 = ([string]$entry.sha256).ToLowerInvariant()
                ActualSHA256   = $null
                ExpectedLength = $expectedLength
                ActualLength   = $null
            })
            continue
        }

        Assert-ICPathHasNoReparsePoint -BasePath $rootFull -FullPath $fullPath
        $item = Get-Item -LiteralPath $fullPath -Force
        $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $status = if (
            $actualHash -eq ([string]$entry.sha256).ToLowerInvariant() -and
            [int64]$item.Length -eq $expectedLength
        ) { 'Valid' } else { 'Modified' }

        [void]$fileResults.Add([pscustomobject][ordered]@{
            Path           = $path
            Status         = $status
            ExpectedSHA256 = ([string]$entry.sha256).ToLowerInvariant()
            ActualSHA256   = $actualHash
            ExpectedLength = $expectedLength
            ActualLength   = [int64]$item.Length
        })
    }

    $excluded = @('metadata/manifest.json', 'metadata/manifest.sha256')
    foreach ($file in Get-ICSafeTreeFiles -RootPath $rootFull) {
        $relative = Get-ICRelativePath -BasePath $rootFull -Path $file.FullName
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

    $checksumListValid = Test-ICChecksumList -CapsuleRoot $rootFull -ManifestEntries $entries
    $missing = @($fileResults | Where-Object Status -eq 'Missing').Count
    $modified = @($fileResults | Where-Object Status -eq 'Modified').Count
    $unexpected = @($fileResults | Where-Object Status -eq 'Unexpected').Count
    $valid = @($fileResults | Where-Object Status -eq 'Valid').Count

    return [pscustomobject][ordered]@{
        PSTypeName        = 'IncidentCapsule.IntegrityResult'
        Path              = $rootFull
        SourceType        = 'Directory'
        CapsuleId         = [string]$manifest.capsuleId
        SchemaVersion     = [string]$manifest.schemaVersion
        Algorithm         = [string]$manifest.algorithm
        IsValid           = ($missing -eq 0 -and $modified -eq 0 -and $unexpected -eq 0 -and $checksumListValid)
        ArchiveHashValid  = $null
        ChecksumListValid = $checksumListValid
        FilesExpected     = $entries.Count
        FilesValid        = $valid
        FilesMissing      = $missing
        FilesModified     = $modified
        FilesUnexpected   = $unexpected
        FileResults       = @($fileResults)
    }
}

function Test-ICArchiveEntryType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $attributeBytes = [System.BitConverter]::GetBytes([int]$Entry.ExternalAttributes)
    $attributes = [System.BitConverter]::ToUInt32($attributeBytes, 0)
    $unixType = (($attributes -shr 16) -band 0xF000)
    $windowsAttributes = ($attributes -band 0xFFFF)

    if ($unixType -eq 0xA000 -or (($windowsAttributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Archive entry '$($Entry.FullName)' represents a symbolic link or reparse point."
    }
}

function Expand-ICArchiveSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [Parameter(Mandatory)]
        [int]$MaximumEntries,

        [Parameter(Mandatory)]
        [int64]$MaximumEntryBytes,

        [Parameter(Mandatory)]
        [int64]$MaximumExpandedBytes,

        [Parameter(Mandatory)]
        [int]$MaximumCompressionRatio
    )

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $entryCount = 0
    $expandedBytes = 0L

    try {
        foreach ($entry in $archive.Entries) {
            $entryCount++
            if ($entryCount -gt $MaximumEntries) {
                throw "Archive contains more than the allowed $MaximumEntries entries."
            }

            Test-ICArchiveEntryType -Entry $entry
            $isDirectory = [string]::IsNullOrEmpty($entry.Name) -or $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')
            $resolved = Resolve-ICContainedPath -BasePath $DestinationPath -RelativePath ([string]$entry.FullName) -AllowDirectory:$isDirectory
            if (-not $seen.Add($resolved.RelativePath)) {
                throw "Archive contains duplicate path '$($resolved.RelativePath)'."
            }

            if ($isDirectory) {
                New-Item -ItemType Directory -Path $resolved.FullPath -Force | Out-Null
                continue
            }

            if ([int64]$entry.Length -gt $MaximumEntryBytes) {
                throw "Archive entry '$($entry.FullName)' exceeds the per-entry size limit."
            }

            $expandedBytes += [int64]$entry.Length
            if ($expandedBytes -gt $MaximumExpandedBytes) {
                throw 'Archive exceeds the allowed expanded-size limit.'
            }

            if ([int64]$entry.Length -gt 0) {
                $compressedLength = [math]::Max([int64]$entry.CompressedLength, 1L)
                $ratio = [double]$entry.Length / [double]$compressedLength
                if ($ratio -gt [double]$MaximumCompressionRatio) {
                    throw "Archive entry '$($entry.FullName)' exceeds the compression-ratio limit."
                }
            }

            $parent = Split-Path -Parent $resolved.FullPath
            if (-not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }

            $inputStream = $entry.Open()
            $outputStream = New-Object -TypeName System.IO.FileStream -ArgumentList @(
                $resolved.FullPath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            try {
                $buffer = New-Object byte[] 81920
                $written = 0L
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $read
                    if ($written -gt [int64]$entry.Length -or $written -gt $MaximumEntryBytes) {
                        throw "Archive entry '$($entry.FullName)' expanded beyond its declared or allowed size."
                    }
                    $outputStream.Write($buffer, 0, $read)
                }
            }
            finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }

            if ((Get-Item -LiteralPath $resolved.FullPath -Force).Length -ne [int64]$entry.Length) {
                throw "Archive entry '$($entry.FullName)' did not extract to its declared length."
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    return [pscustomobject][ordered]@{
        EntryCount          = $entryCount
        ExpandedBytes       = $expandedBytes
        MaximumEntries      = $MaximumEntries
        MaximumEntryBytes   = $MaximumEntryBytes
        MaximumExpandedBytes = $MaximumExpandedBytes
        MaximumCompressionRatio = $MaximumCompressionRatio
    }
}

function Test-ICArchiveIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [int]$MaximumArchiveEntries = 20000,

        [int64]$MaximumArchiveEntryBytes = 1073741824L,

        [int64]$MaximumArchiveExpandedBytes = 10737418240L,

        [int]$MaximumArchiveCompressionRatio = 250
    )

    $resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath -ErrorAction Stop).Path
    $archiveHashValid = $null
    $sidecarPath = "$resolvedArchive.sha256"
    if (Test-Path -LiteralPath $sidecarPath -PathType Leaf) {
        $line = Get-Content -LiteralPath $sidecarPath -Encoding UTF8 | Select-Object -First 1
        if ([string]$line -notmatch '^([a-fA-F0-9]{64})\s{2}(.+)$') {
            throw "Sidecar '$sidecarPath' does not contain a valid SHA-256 record."
        }
        $expectedHash = $Matches[1].ToLowerInvariant()
        $expectedName = $Matches[2]
        if ($expectedName -ne (Split-Path -Leaf $resolvedArchive)) {
            throw "Sidecar '$sidecarPath' names '$expectedName' instead of the archive file."
        }
        $actualHash = (Get-FileHash -LiteralPath $resolvedArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        $archiveHashValid = $actualHash -eq $expectedHash
    }

    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("incident-capsule-verify-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    try {
        $archivePolicy = Expand-ICArchiveSafely `
            -ArchivePath $resolvedArchive `
            -DestinationPath $temporaryRoot `
            -MaximumEntries $MaximumArchiveEntries `
            -MaximumEntryBytes $MaximumArchiveEntryBytes `
            -MaximumExpandedBytes $MaximumArchiveExpandedBytes `
            -MaximumCompressionRatio $MaximumArchiveCompressionRatio

        $root = Find-ICManifestRoot -Path $temporaryRoot
        $result = Test-ICDirectoryIntegrity -CapsuleRoot $root
        $result.Path = $resolvedArchive
        $result.SourceType = 'Archive'
        $result.ArchiveHashValid = $archiveHashValid
        $result | Add-Member -NotePropertyName ArchivePolicy -NotePropertyValue $archivePolicy
        if ($archiveHashValid -eq $false) {
            $result.IsValid = $false
        }
        return $result
    }
    finally {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-ICVerificationReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [object]$Verification
    )

    $receiptPath = "$ArchivePath.verification.json"
    $receipt = [ordered]@{
        '$schema'          = 'https://raw.githubusercontent.com/xGreeny/incident-capsule/v$($script:ICVersion)/docs/schemas/verification-receipt.schema.json'
        schemaVersion      = $script:ICSchemaVersion
        verifiedAtUtc      = [datetime]::UtcNow.ToString('o')
        verifier = [ordered]@{
            name    = $script:ICName
            version = $script:ICVersion
        }
        archive            = Split-Path -Leaf $ArchivePath
        capsuleId          = $Verification.CapsuleId
        isValid            = [bool]$Verification.IsValid
        archiveHashValid   = $Verification.ArchiveHashValid
        checksumListValid  = $Verification.ChecksumListValid
        filesExpected      = $Verification.FilesExpected
        filesValid         = $Verification.FilesValid
        filesMissing       = $Verification.FilesMissing
        filesModified      = $Verification.FilesModified
        filesUnexpected    = $Verification.FilesUnexpected
        archivePolicy      = $Verification.ArchivePolicy
    }

    [void](Write-ICJsonFile -Path $receiptPath -InputObject $receipt -Depth 12)
    return $receiptPath
}

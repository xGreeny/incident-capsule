function Test-ICObjectProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Resolve-ICSafeRelativePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativePath,

        [Parameter(Mandatory)]
        [string]$RootPath,

        [string]$Description = 'Path'
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "$Description cannot be empty."
    }
    if ($RelativePath.Length -gt 1024) {
        throw "$Description exceeds the 1024-character safety limit."
    }
    if ($RelativePath.IndexOf([char]0) -ge 0) {
        throw "$Description contains a NUL character."
    }
    if ([System.IO.Path]::IsPathRooted($RelativePath) -or $RelativePath -match '^[A-Za-z]:') {
        throw "$Description '$RelativePath' must be relative."
    }

    $normalized = $RelativePath.Replace([char]'\', [char]'/')
    if ($normalized.StartsWith('/') -or $normalized.EndsWith('/')) {
        throw "$Description '$RelativePath' has an empty path segment."
    }

    $segments = @($normalized -split '/')
    if ($segments.Count -eq 0) {
        throw "$Description '$RelativePath' is invalid."
    }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..') {
            throw "$Description '$RelativePath' contains an unsafe path segment."
        }
        if ($segment.Length -gt 255) {
            throw "$Description '$RelativePath' contains a path segment longer than 255 characters."
        }
        if ($segment -match '[<>:"|?*\x00-\x1f]' -or $segment -match '[\. ]$') {
            throw "$Description '$RelativePath' contains characters that are unsafe on Windows."
        }
        if ($segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
            throw "$Description '$RelativePath' contains a reserved Windows device name."
        }
    }

    $rootFull = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([char]'\', [char]'/')
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull ($normalized -replace '/', [System.IO.Path]::DirectorySeparatorChar)))
    $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description '$RelativePath' resolves outside '$rootFull'."
    }

    return [pscustomobject][ordered]@{
        RelativePath = $normalized
        FullPath     = $candidate
        Segments     = @($segments)
    }
}

function Assert-ICNoReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([char]'\', [char]'/')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if ($pathFull -ne $rootFull -and -not $pathFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$pathFull' is outside capsule root '$rootFull'."
    }

    $paths = New-Object System.Collections.Generic.List[string]
    $paths.Add($rootFull)
    if ($pathFull -ne $rootFull) {
        $relative = $pathFull.Substring($rootPrefix.Length)
        $current = $rootFull
        foreach ($segment in @($relative -split '[\\/]')) {
            $current = Join-Path $current $segment
            $paths.Add($current)
        }
    }

    foreach ($candidate in $paths) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            break
        }
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point '$candidate' is not permitted inside a capsule."
        }
    }
}

function Get-ICSafeCapsuleFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    $rootFull = [System.IO.Path]::GetFullPath($CapsuleRoot).TrimEnd([char]'\', [char]'/')
    Assert-ICNoReparsePoint -RootPath $rootFull -Path $rootFull

    $directories = New-Object 'System.Collections.Generic.Queue[string]'
    $directories.Enqueue($rootFull)
    $files = New-Object System.Collections.ArrayList
    while ($directories.Count -gt 0) {
        $directory = $directories.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse point '$($item.FullName)' is not permitted inside a capsule."
            }
            if ($item.PSIsContainer) {
                $directories.Enqueue($item.FullName)
            }
            else {
                [void]$files.Add($item)
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

    $excluded = @('metadata/manifest.json', 'metadata/manifest.sha256', 'metadata/manifest.sha256.p7s')
    return @(
        Get-ICSafeCapsuleFile -CapsuleRoot $CapsuleRoot |
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
    Assert-ICNoReparsePoint -RootPath $CapsuleRoot -Path $metadataDirectory

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

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

    $rootFull = [System.IO.Path]::GetFullPath($CapsuleRoot).TrimEnd([char]'\', [char]'/')
    $archivePath = "$rootFull.zip"
    $sidecarPath = "$archivePath.sha256"
    if (Test-Path -LiteralPath $archivePath) {
        throw "Archive '$archivePath' already exists."
    }
    if (Test-Path -LiteralPath $sidecarPath) {
        throw "Archive sidecar '$sidecarPath' already exists."
    }

    $archiveDirectory = [System.IO.Path]::GetDirectoryName($archivePath)
    $temporaryPath = Join-Path $archiveDirectory ('.{0}.{1}.partial' -f [System.IO.Path]::GetFileName($archivePath), [guid]::NewGuid().ToString('N'))
    try {
        $files = @(Get-ICSafeCapsuleFile -CapsuleRoot $rootFull | Sort-Object FullName)
        $archive = [System.IO.Compression.ZipFile]::Open($temporaryPath, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($file in $files) {
                Assert-ICNoReparsePoint -RootPath $rootFull -Path $file.FullName
                $relativePath = Get-ICRelativePath -BasePath $rootFull -Path $file.FullName
                $zipEntry = $archive.CreateEntry($relativePath, [System.IO.Compression.CompressionLevel]::Optimal)
                if ($file.LastWriteTimeUtc.Year -ge 1980 -and $file.LastWriteTimeUtc.Year -le 2107) {
                    $zipEntry.LastWriteTime = New-Object System.DateTimeOffset($file.LastWriteTimeUtc)
                }

                $sourceStream = $null
                $destinationStream = $null
                try {
                    $sourceStream = New-Object System.IO.FileStream(
                        $file.FullName,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read,
                        [System.IO.FileShare]::Read
                    )
                    $destinationStream = $zipEntry.Open()
                    $sourceStream.CopyTo($destinationStream)
                }
                finally {
                    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
                    if ($null -ne $destinationStream) { $destinationStream.Dispose() }
                }
            }
        }
        finally {
            $archive.Dispose()
        }

        $hash = Get-FileHash -LiteralPath $temporaryPath -Algorithm SHA256 -ErrorAction Stop
        [System.IO.File]::Move($temporaryPath, $archivePath)

        $line = '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), (Split-Path -Leaf $archivePath)
        [void](Write-ICUtf8File -Path $sidecarPath -Content ($line + [Environment]::NewLine))

        return [pscustomobject][ordered]@{
            ArchivePath = $archivePath
            SidecarPath = $sidecarPath
            SHA256      = $hash.Hash.ToLowerInvariant()
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Find-ICManifestRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $root = [System.IO.Path]::GetFullPath($Path).TrimEnd([char]'\', [char]'/')
    Assert-ICNoReparsePoint -RootPath $root -Path $root
    $direct = Join-Path $root 'metadata/manifest.json'
    Assert-ICNoReparsePoint -RootPath $root -Path $direct
    if (Test-Path -LiteralPath $direct -PathType Leaf) {
        return $root
    }

    $files = @(Get-ICSafeCapsuleFile -CapsuleRoot $root)
    $manifests = @($files | Where-Object {
        $_.Name -eq 'manifest.json' -and (Split-Path -Leaf (Split-Path -Parent $_.FullName)) -eq 'metadata'
    })

    if ($manifests.Count -ne 1) {
        throw "Expected exactly one metadata/manifest.json below '$root'; found $($manifests.Count)."
    }

    $manifestRoot = Split-Path -Parent (Split-Path -Parent $manifests[0].FullName)
    $manifestRootFull = [System.IO.Path]::GetFullPath($manifestRoot).TrimEnd([char]'\', [char]'/')
    $manifestRootPrefix = $manifestRootFull + [System.IO.Path]::DirectorySeparatorChar
    $outsideFiles = @($files | Where-Object {
        -not $_.FullName.StartsWith($manifestRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($outsideFiles.Count -gt 0) {
        throw "Found $($outsideFiles.Count) file(s) outside the directory containing metadata/manifest.json."
    }

    return $manifestRootFull
}

function Read-ICValidatedManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot
    )

    $root = [System.IO.Path]::GetFullPath($CapsuleRoot).TrimEnd([char]'\', [char]'/')
    $manifestPath = Join-Path $root 'metadata/manifest.json'
    Assert-ICNoReparsePoint -RootPath $root -Path $manifestPath
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Manifest not found at '$manifestPath'."
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Manifest '$manifestPath' is not valid JSON: $($_.Exception.Message)"
    }

    if ($null -eq $manifest -or $manifest -is [System.Array]) {
        throw "Manifest '$manifestPath' must contain one JSON object."
    }
    if (-not (Test-ICObjectProperty -InputObject $manifest -Name 'schemaVersion')) {
        throw "Manifest '$manifestPath' does not contain a schemaVersion."
    }
    $schemaVersion = [string](Get-ICPropertyValue -InputObject $manifest -Name 'schemaVersion')
    if ($schemaVersion -notin @('1.0', '1.1', '1.2')) {
        throw "Manifest '$manifestPath' uses unsupported schema version '$schemaVersion'."
    }
    if (-not (Test-ICObjectProperty -InputObject $manifest -Name 'algorithm') -or [string]$manifest.algorithm -ne 'SHA-256') {
        throw "Manifest '$manifestPath' must specify the SHA-256 algorithm."
    }
    if (-not (Test-ICObjectProperty -InputObject $manifest -Name 'capsuleId') -or [string]::IsNullOrWhiteSpace([string]$manifest.capsuleId)) {
        throw "Manifest '$manifestPath' does not contain a valid capsuleId."
    }
    if (-not (Test-ICObjectProperty -InputObject $manifest -Name 'files')) {
        throw "Manifest '$manifestPath' does not contain a files array."
    }
    $rawFiles = $manifest.PSObject.Properties['files'].Value
    if ($null -eq $rawFiles -or $rawFiles -isnot [System.Array]) {
        throw "Manifest '$manifestPath' files value must be an array."
    }

    $validatedEntries = New-Object System.Collections.ArrayList
    $expectedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $index = -1
    foreach ($entry in @($rawFiles)) {
        $index++
        if ($null -eq $entry -or $entry -is [string]) {
            throw "Manifest file entry $index must be an object."
        }
        foreach ($required in @('path', 'length', 'lastWriteTimeUtc', 'sha256')) {
            if (-not (Test-ICObjectProperty -InputObject $entry -Name $required)) {
                throw "Manifest file entry $index is missing '$required'."
            }
        }

        $validatedPath = Resolve-ICSafeRelativePath -RelativePath ([string]$entry.path) -RootPath $root -Description "Manifest path at index $index"
        if ($validatedPath.RelativePath -in @('metadata/manifest.json', 'metadata/manifest.sha256', 'metadata/manifest.sha256.p7s')) {
            throw "Manifest file entry $index references a manifest control file."
        }
        if (-not $expectedPaths.Add($validatedPath.RelativePath)) {
            throw "Manifest contains a duplicate or case-colliding path '$($validatedPath.RelativePath)'."
        }

        $lengthValue = Get-ICPropertyValue -InputObject $entry -Name 'length'
        if ($lengthValue -isnot [byte] -and $lengthValue -isnot [int16] -and $lengthValue -isnot [int32] -and $lengthValue -isnot [int64] -and
            $lengthValue -isnot [uint16] -and $lengthValue -isnot [uint32]) {
            throw "Manifest file entry '$($validatedPath.RelativePath)' has a non-integer length."
        }
        if ([int64]$lengthValue -lt 0) {
            throw "Manifest file entry '$($validatedPath.RelativePath)' has a negative length."
        }

        $hash = [string](Get-ICPropertyValue -InputObject $entry -Name 'sha256')
        if ($hash -cnotmatch '^[a-fA-F0-9]{64}$') {
            throw "Manifest file entry '$($validatedPath.RelativePath)' has an invalid SHA-256 value."
        }

        $lastWrite = [string](Get-ICPropertyValue -InputObject $entry -Name 'lastWriteTimeUtc')
        $parsedDate = [datetime]::MinValue
        if (-not [datetime]::TryParse(
            $lastWrite,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsedDate
        )) {
            throw "Manifest file entry '$($validatedPath.RelativePath)' has an invalid lastWriteTimeUtc value."
        }

        [void]$validatedEntries.Add([pscustomobject][ordered]@{
            Path           = $validatedPath.RelativePath
            FullPath       = $validatedPath.FullPath
            ExpectedLength = [int64]$lengthValue
            ExpectedSHA256 = $hash.ToLowerInvariant()
        })
    }

    return [pscustomobject][ordered]@{
        Manifest = $manifest
        Entries  = @($validatedEntries)
    }
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

    Assert-ICNoReparsePoint -RootPath $CapsuleRoot -Path $checksumPath
    $expected = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($ManifestEntries)) {
        $path = [string](Get-ICPropertyValue -InputObject $entry -Name 'Path' -Default (Get-ICPropertyValue -InputObject $entry -Name 'path'))
        $hash = [string](Get-ICPropertyValue -InputObject $entry -Name 'ExpectedSHA256' -Default (Get-ICPropertyValue -InputObject $entry -Name 'sha256'))
        $validated = Resolve-ICSafeRelativePath -RelativePath $path -RootPath $CapsuleRoot -Description 'Checksum-list path'
        if ($hash -cnotmatch '^[a-fA-F0-9]{64}$' -or $expected.ContainsKey($validated.RelativePath)) {
            return $false
        }
        $expected.Add($validated.RelativePath, $hash.ToLowerInvariant())
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
        try {
            $validated = Resolve-ICSafeRelativePath -RelativePath $Matches[2] -RootPath $CapsuleRoot -Description 'Checksum-list path'
        }
        catch {
            return $false
        }
        $path = $validated.RelativePath
        if (-not $seen.Add($path)) { return $false }
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

    $root = [System.IO.Path]::GetFullPath($CapsuleRoot).TrimEnd([char]'\', [char]'/')
    $validatedManifest = Read-ICValidatedManifest -CapsuleRoot $root
    $manifest = $validatedManifest.Manifest
    $entries = @($validatedManifest.Entries)

    $fileResults = New-Object System.Collections.ArrayList
    $expected = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        [void]$expected.Add($entry.Path)
        Assert-ICNoReparsePoint -RootPath $root -Path $entry.FullPath
        if (-not (Test-Path -LiteralPath $entry.FullPath -PathType Leaf)) {
            [void]$fileResults.Add([pscustomobject][ordered]@{
                Path           = $entry.Path
                Status         = 'Missing'
                ExpectedSHA256 = $entry.ExpectedSHA256
                ActualSHA256   = $null
                ExpectedLength = $entry.ExpectedLength
                ActualLength   = $null
            })
            continue
        }

        $item = Get-Item -LiteralPath $entry.FullPath -Force -ErrorAction Stop
        $actualHash = (Get-FileHash -LiteralPath $entry.FullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $status = if ($actualHash -eq $entry.ExpectedSHA256 -and [int64]$item.Length -eq $entry.ExpectedLength) { 'Valid' } else { 'Modified' }

        [void]$fileResults.Add([pscustomobject][ordered]@{
            Path           = $entry.Path
            Status         = $status
            ExpectedSHA256 = $entry.ExpectedSHA256
            ActualSHA256   = $actualHash
            ExpectedLength = $entry.ExpectedLength
            ActualLength   = [int64]$item.Length
        })
    }

    $excluded = @('metadata/manifest.json', 'metadata/manifest.sha256', 'metadata/manifest.sha256.p7s')
    foreach ($file in Get-ICSafeCapsuleFile -CapsuleRoot $root) {
        $relative = Get-ICRelativePath -BasePath $root -Path $file.FullName
        if ($relative -in $excluded) {
            continue
        }
        if (-not $expected.Contains($relative)) {
            [void]$fileResults.Add([pscustomobject][ordered]@{
                Path           = $relative
                Status         = 'Unexpected'
                ExpectedSHA256 = $null
                ActualSHA256   = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                ExpectedLength = $null
                ActualLength   = [int64]$file.Length
            })
        }
    }

    $checksumListValid = Test-ICChecksumList -CapsuleRoot $root -ManifestEntries $entries
    $missing = @($fileResults | Where-Object Status -eq 'Missing').Count
    $modified = @($fileResults | Where-Object Status -eq 'Modified').Count
    $unexpected = @($fileResults | Where-Object Status -eq 'Unexpected').Count
    $valid = @($fileResults | Where-Object Status -eq 'Valid').Count

    $signaturePresent = $false
    $signatureValid = $null
    $signatureChainValid = $null
    $signerSubject = $null
    $signerThumbprint = $null
    $signaturePath = Join-Path $root 'metadata/manifest.sha256.p7s'
    if (Test-Path -LiteralPath $signaturePath -PathType Leaf) {
        Assert-ICNoReparsePoint -RootPath $root -Path $signaturePath
        $signaturePresent = $true
        $signature = Test-ICManifestSignature -ManifestTextPath (Join-Path $root 'metadata/manifest.sha256') -SignaturePath $signaturePath
        $signatureValid = [bool]$signature.SignatureValid
        $signatureChainValid = $signature.ChainValid
        $signerSubject = $signature.SignerSubject
        $signerThumbprint = $signature.SignerThumbprint
    }

    return [pscustomobject][ordered]@{
        PSTypeName          = 'IncidentCapsule.IntegrityResult'
        Path                = $root
        SourceType          = 'Directory'
        CapsuleId           = [string]$manifest.capsuleId
        SchemaVersion       = [string]$manifest.schemaVersion
        Algorithm           = [string]$manifest.algorithm
        IsValid             = ($missing -eq 0 -and $modified -eq 0 -and $unexpected -eq 0 -and $checksumListValid -and ($signatureValid -ne $false))
        ArchiveHashValid    = $null
        ChecksumListValid   = $checksumListValid
        SignaturePresent    = $signaturePresent
        SignatureValid      = $signatureValid
        SignatureChainValid = $signatureChainValid
        SignerSubject       = $signerSubject
        SignerThumbprint    = $signerThumbprint
        FilesExpected       = $entries.Count
        FilesValid          = $valid
        FilesMissing        = $missing
        FilesModified       = $modified
        FilesUnexpected     = $unexpected
        FileResults         = @($fileResults)
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

function Get-ICValidatedZipEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchive]$Archive,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter(Mandatory)]
        [int]$MaximumArchiveEntries,

        [Parameter(Mandatory)]
        [int64]$MaximumArchiveEntryBytes,

        [Parameter(Mandatory)]
        [int64]$MaximumArchiveExpandedBytes,

        [Parameter(Mandatory)]
        [double]$MaximumArchiveCompressionRatio
    )

    if ($Archive.Entries.Count -gt $MaximumArchiveEntries) {
        throw "Archive contains $($Archive.Entries.Count) entries; the limit is $MaximumArchiveEntries."
    }

    $validated = New-Object System.Collections.ArrayList
    $entryTypes = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    [int64]$totalLength = 0
    [int64]$totalCompressedLength = 0

    foreach ($entry in $Archive.Entries) {
        Test-ICArchiveEntryType -Entry $entry
        $rawName = [string]$entry.FullName
        if ([string]::IsNullOrWhiteSpace($rawName)) {
            throw 'Archive contains an entry with an empty name.'
        }

        $isDirectory = $rawName.EndsWith('/') -or $rawName.EndsWith('\')
        $pathForValidation = if ($isDirectory) { $rawName.TrimEnd([char]'/', [char]'\') } else { $rawName }
        $safePath = Resolve-ICSafeRelativePath -RelativePath $pathForValidation -RootPath $DestinationRoot -Description 'Archive entry'

        if ($entryTypes.ContainsKey($safePath.RelativePath)) {
            throw "Archive contains duplicate or case-colliding entry '$($safePath.RelativePath)'."
        }

        $segments = @($safePath.Segments)
        for ($index = 1; $index -lt $segments.Count; $index++) {
            $ancestor = ($segments[0..($index - 1)] -join '/')
            if ($entryTypes.ContainsKey($ancestor) -and $entryTypes[$ancestor] -eq 'File') {
                throw "Archive entry '$($safePath.RelativePath)' is nested below file '$ancestor'."
            }
        }
        if (-not $isDirectory) {
            $descendantPrefix = $safePath.RelativePath + '/'
            foreach ($knownPath in @($entryTypes.Keys)) {
                if ($knownPath.StartsWith($descendantPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Archive file '$($safePath.RelativePath)' collides with child entry '$knownPath'."
                }
            }
        }

        if ($isDirectory -and ([int64]$entry.Length -ne 0 -or [int64]$entry.CompressedLength -ne 0)) {
            throw "Archive directory entry '$($safePath.RelativePath)' contains data."
        }
        if (-not $isDirectory) {
            if ([int64]$entry.Length -gt $MaximumArchiveEntryBytes) {
                throw "Archive entry '$($safePath.RelativePath)' exceeds the $MaximumArchiveEntryBytes-byte per-entry size limit."
            }
            if ([int64]$entry.Length -gt $MaximumArchiveExpandedBytes - $totalLength) {
                throw "Archive uncompressed size (expanded) exceeds the $MaximumArchiveExpandedBytes-byte limit."
            }
            $totalLength += [int64]$entry.Length
            $totalCompressedLength += [int64]$entry.CompressedLength

            $entryRatio = if ([int64]$entry.Length -eq 0) {
                0.0
            }
            elseif ([int64]$entry.CompressedLength -eq 0) {
                [double]::PositiveInfinity
            }
            else {
                [double]$entry.Length / [double]$entry.CompressedLength
            }
            if ($entryRatio -gt $MaximumArchiveCompressionRatio) {
                throw "Archive entry '$($safePath.RelativePath)' has compression ratio $([math]::Round($entryRatio, 2)); the limit is $MaximumArchiveCompressionRatio."
            }
        }

        $entryTypes.Add($safePath.RelativePath, $(if ($isDirectory) { 'Directory' } else { 'File' }))
        [void]$validated.Add([pscustomobject][ordered]@{
            ZipEntry      = $entry
            RelativePath = $safePath.RelativePath
            FullPath     = $safePath.FullPath
            Segments     = @($safePath.Segments)
            IsDirectory  = $isDirectory
            Length       = [int64]$entry.Length
        })
    }

    $aggregateRatio = if ($totalLength -eq 0) {
        0.0
    }
    elseif ($totalCompressedLength -eq 0) {
        [double]::PositiveInfinity
    }
    else {
        [double]$totalLength / [double]$totalCompressedLength
    }
    if ($aggregateRatio -gt $MaximumArchiveCompressionRatio) {
        throw "Archive aggregate compression ratio $([math]::Round($aggregateRatio, 2)) exceeds the limit of $MaximumArchiveCompressionRatio."
    }

    return [pscustomobject][ordered]@{
        Entries          = @($validated)
        EntryCount       = $Archive.Entries.Count
        ExpandedBytes    = $totalLength
        UncompressedBytes = $totalLength
        CompressionRatio = $aggregateRatio
    }
}

function New-ICSafeExtractionDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter(Mandatory)]
        [string[]]$Segments
    )

    $current = [System.IO.Path]::GetFullPath($DestinationRoot).TrimEnd([char]'\', [char]'/')
    Assert-ICNoReparsePoint -RootPath $current -Path $current
    foreach ($segment in $Segments) {
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            if (-not (Test-Path -LiteralPath $current -PathType Container)) {
                throw "Archive extraction path '$current' collides with a file."
            }
        }
        else {
            New-Item -ItemType Directory -Path $current -ErrorAction Stop | Out-Null
        }
        Assert-ICNoReparsePoint -RootPath $DestinationRoot -Path $current
    }

    return $current
}

function Expand-ICZipArchiveSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [int]$MaximumArchiveEntries = 20000,

        [int64]$MaximumArchiveEntryBytes = 1073741824L,

        [Alias('MaximumArchiveUncompressedBytes')]
        [int64]$MaximumArchiveExpandedBytes = 21474836480L,

        [double]$MaximumArchiveCompressionRatio = 250
    )

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $DestinationPath -PathType Container)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force -ErrorAction Stop | Out-Null
    }
    Assert-ICNoReparsePoint -RootPath $DestinationPath -Path $DestinationPath

    $stream = New-Object System.IO.FileStream(
        $ArchivePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $archive = $null
    try {
        $archive = New-Object System.IO.Compression.ZipArchive(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Read,
            $false
        )
        $validation = Get-ICValidatedZipEntry `
            -Archive $archive `
            -DestinationRoot $DestinationPath `
            -MaximumArchiveEntries $MaximumArchiveEntries `
            -MaximumArchiveEntryBytes $MaximumArchiveEntryBytes `
            -MaximumArchiveExpandedBytes $MaximumArchiveExpandedBytes `
            -MaximumArchiveCompressionRatio $MaximumArchiveCompressionRatio

        [int64]$extractedBytes = 0
        foreach ($entry in @($validation.Entries)) {
            if ($entry.IsDirectory) {
                [void](New-ICSafeExtractionDirectory -DestinationRoot $DestinationPath -Segments $entry.Segments)
                continue
            }

            $parentSegments = @()
            if ($entry.Segments.Count -gt 1) {
                $parentSegments = @($entry.Segments[0..($entry.Segments.Count - 2)])
            }
            if ($parentSegments.Count -gt 0) {
                [void](New-ICSafeExtractionDirectory -DestinationRoot $DestinationPath -Segments $parentSegments)
            }
            Assert-ICNoReparsePoint -RootPath $DestinationPath -Path ([System.IO.Path]::GetDirectoryName($entry.FullPath))

            $inputStream = $null
            $output = $null
            [int64]$entryBytes = 0
            try {
                $inputStream = $entry.ZipEntry.Open()
                $output = New-Object System.IO.FileStream(
                    $entry.FullPath,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
                $buffer = New-Object byte[] 65536
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if (
                        $entryBytes + $read -gt $entry.Length -or
                        $entryBytes + $read -gt $MaximumArchiveEntryBytes -or
                        $extractedBytes + $read -gt $MaximumArchiveExpandedBytes
                    ) {
                        throw "Archive entry '$($entry.RelativePath)' exceeded its validated extraction bound."
                    }
                    $output.Write($buffer, 0, $read)
                    $entryBytes += $read
                    $extractedBytes += $read
                }
                $output.Flush($true)
            }
            finally {
                if ($null -ne $inputStream) { $inputStream.Dispose() }
                if ($null -ne $output) { $output.Dispose() }
            }

            if ($entryBytes -ne $entry.Length) {
                throw "Archive entry '$($entry.RelativePath)' length changed during extraction."
            }
        }

        return [pscustomobject][ordered]@{
            EntryCount                    = $validation.EntryCount
            ExpandedBytes                 = $extractedBytes
            UncompressedBytes             = $extractedBytes
            CompressionRatio              = $validation.CompressionRatio
            MaximumEntries                = $MaximumArchiveEntries
            MaximumEntryBytes             = $MaximumArchiveEntryBytes
            MaximumExpandedBytes          = $MaximumArchiveExpandedBytes
            MaximumCompressionRatio       = $MaximumArchiveCompressionRatio
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        else { $stream.Dispose() }
    }
}

function Test-ICArchiveIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [switch]$RequireSidecar,

        [switch]$RequireSignature,

        [int]$MaximumArchiveEntries = 20000,

        [int64]$MaximumArchiveEntryBytes = 1073741824L,

        [Alias('MaximumArchiveUncompressedBytes')]
        [int64]$MaximumArchiveExpandedBytes = 21474836480L,

        [double]$MaximumArchiveCompressionRatio = 250
    )

    $resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath -ErrorAction Stop).Path
    $archiveHashValid = $null
    $sidecarPath = "$resolvedArchive.sha256"
    if (Test-Path -LiteralPath $sidecarPath -PathType Leaf) {
        $line = [string](Get-Content -LiteralPath $sidecarPath -Encoding UTF8 -ErrorAction Stop | Select-Object -First 1)
        if ($line -notmatch '^\s*([a-fA-F0-9]{64})(?:\s+(.+?))?\s*$') {
            throw "Sidecar '$sidecarPath' does not contain a valid SHA-256 value."
        }
        $expectedHash = $Matches[1].ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace([string]$Matches[2])) {
            $expectedName = ([string]$Matches[2]).Trim().TrimStart([char]'*')
            if ($expectedName -ne (Split-Path -Leaf $resolvedArchive)) {
                throw "Sidecar '$sidecarPath' names '$expectedName' instead of the selected archive."
            }
        }
        $actualHash = (Get-FileHash -LiteralPath $resolvedArchive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $archiveHashValid = $actualHash -eq $expectedHash
    }
    elseif ($RequireSidecar) {
        throw "Required archive sidecar '$sidecarPath' was not found."
    }

    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("incident-capsule-verify-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryRoot -Force -ErrorAction Stop | Out-Null
    try {
        $archivePolicy = Expand-ICZipArchiveSafely `
            -ArchivePath $resolvedArchive `
            -DestinationPath $temporaryRoot `
            -MaximumArchiveEntries $MaximumArchiveEntries `
            -MaximumArchiveEntryBytes $MaximumArchiveEntryBytes `
            -MaximumArchiveExpandedBytes $MaximumArchiveExpandedBytes `
            -MaximumArchiveCompressionRatio $MaximumArchiveCompressionRatio

        $root = Find-ICManifestRoot -Path $temporaryRoot
        $result = Test-ICDirectoryIntegrity -CapsuleRoot $root
        if ($RequireSignature -and -not $result.SignaturePresent) {
            throw "Required manifest signature 'metadata/manifest.sha256.p7s' was not found in the archive."
        }
        $result.Path = $resolvedArchive
        $result.SourceType = 'Archive'
        $result.ArchiveHashValid = $archiveHashValid
        $result | Add-Member -NotePropertyName ArchivePolicy -NotePropertyValue $archivePolicy
        $result | Add-Member -NotePropertyName ArchiveEntryCount -NotePropertyValue $archivePolicy.EntryCount
        $result | Add-Member -NotePropertyName ArchiveUncompressedBytes -NotePropertyValue $archivePolicy.ExpandedBytes
        $result | Add-Member -NotePropertyName ArchiveCompressionRatio -NotePropertyValue $archivePolicy.CompressionRatio
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
        '$schema'          = $script:ICVerificationReceiptSchema
        schemaVersion      = $script:ICSchemaVersion
        verifiedAtUtc      = [datetime]::UtcNow.ToString('o')
        verifier           = [ordered]@{
            name    = $script:ICName
            version = $script:ICVersion
        }
        archive            = Split-Path -Leaf $ArchivePath
        capsuleId          = $Verification.CapsuleId
        isValid            = [bool]$Verification.IsValid
        archiveHashValid   = $Verification.ArchiveHashValid
        checksumListValid  = [bool]$Verification.ChecksumListValid
        filesExpected      = $Verification.FilesExpected
        filesValid         = $Verification.FilesValid
        filesMissing       = $Verification.FilesMissing
        filesModified      = $Verification.FilesModified
        filesUnexpected    = $Verification.FilesUnexpected
        signaturePresent   = [bool](Get-ICPropertyValue -InputObject $Verification -Name 'SignaturePresent' -Default $false)
        signatureValid     = Get-ICPropertyValue -InputObject $Verification -Name 'SignatureValid'
        signerSubject      = Get-ICPropertyValue -InputObject $Verification -Name 'SignerSubject'
        signerThumbprint   = Get-ICPropertyValue -InputObject $Verification -Name 'SignerThumbprint'
        archivePolicy      = $Verification.ArchivePolicy
    }

    [void](Write-ICJsonFile -Path $receiptPath -InputObject $receipt -Depth 12)
    return $receiptPath
}

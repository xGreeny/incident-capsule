BeforeAll {
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1') -Force

    function New-TestZipArchive {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [System.Collections.IDictionary[]]$Entries
        )

        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($definition in $Entries) {
                $entry = $archive.CreateEntry([string]$definition.Name, [System.IO.Compression.CompressionLevel]::Optimal)
                $writer = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
                try { $writer.Write([string]$definition.Content) } finally { $writer.Dispose() }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
}

Describe 'Incident Capsule integrity manifest' {
    BeforeEach {
        $capsuleRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $capsuleRoot 'metadata') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $capsuleRoot 'evidence/system') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $capsuleRoot 'logs') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $capsuleRoot 'evidence/system/system.json') -Value '{"test":true}' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $capsuleRoot 'logs/collector.log') -Value 'complete' -Encoding UTF8
    }

    It 'verifies an unchanged directory and checksum list' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $Root
            $result.IsValid | Should -BeTrue
            $result.ChecksumListValid | Should -BeTrue
            $result.FilesExpected | Should -Be 2
            $result.FilesValid | Should -Be 2
        }
    }

    It 'detects a modified file' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            Add-Content -LiteralPath (Join-Path $Root 'logs/collector.log') -Value 'changed'
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $Root
            $result.IsValid | Should -BeFalse
            $result.FilesModified | Should -Be 1
        }
    }

    It 'detects a missing file' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            Remove-Item -LiteralPath (Join-Path $Root 'logs/collector.log')
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $Root
            $result.IsValid | Should -BeFalse
            $result.FilesMissing | Should -Be 1
        }
    }

    It 'detects an unexpected file' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'analyst-note.txt') -Value 'new'
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $Root
            $result.IsValid | Should -BeFalse
            $result.FilesUnexpected | Should -Be 1
        }
    }

    It 'rejects a parent-directory path in a manipulated manifest' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            $manifestPath = Join-Path $Root 'metadata/manifest.json'
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            $manifest.files[0].path = '../outside.txt'
            $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
            { Test-ICDirectoryIntegrity -CapsuleRoot $Root } | Should -Throw '*unsafe path segment*'
        }
    }

    It 'rejects case-insensitive duplicate manifest paths' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            $manifestPath = Join-Path $Root 'metadata/manifest.json'
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            $duplicate = $manifest.files[0].PSObject.Copy()
            $duplicate.path = ([string]$duplicate.path).ToUpperInvariant()
            $manifest.files = @($manifest.files) + @($duplicate)
            $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
            { Test-ICDirectoryIntegrity -CapsuleRoot $Root } | Should -Throw '*duplicate or case-colliding path*'
        }
    }

    It 'fails verification when the checksum list is changed' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'metadata/manifest.sha256') -Value ('0' * 64 + '  evidence/system/system.json')
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $Root
            $result.IsValid | Should -BeFalse
            $result.ChecksumListValid | Should -BeFalse
        }
    }

    It 'verifies a generated archive and its sidecar' {
        $archive = InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            New-ICArchive -CapsuleRoot $Root
        }
        $result = Test-IncidentCapsuleIntegrity -Path $archive.ArchivePath
        $result.IsValid | Should -BeTrue
        $result.ArchiveHashValid | Should -BeTrue
        $result.ChecksumListValid | Should -BeTrue
    }

    It 'writes a versioned external archive verification receipt' {
        $receipt = InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-RECEIPT' | Out-Null
            $archive = New-ICArchive -CapsuleRoot $Root
            $verification = Test-ICArchiveIntegrity -ArchivePath $archive.ArchivePath -RequireSidecar
            $path = Write-ICVerificationReceipt -ArchivePath $archive.ArchivePath -Verification $verification
            [pscustomobject]@{ Path = $path; ArchivePath = $archive.ArchivePath }
        }

        $receipt.Path | Should -Be "$($receipt.ArchivePath).verification.json"
        $document = Get-Content -LiteralPath $receipt.Path -Raw | ConvertFrom-Json
        $moduleVersion = (Get-Module IncidentCapsule).Version.ToString()
        $document.'$schema' | Should -Match ('/v{0}/docs/schemas/verification-receipt\.schema\.json$' -f [regex]::Escape($moduleVersion))
        $document.schemaVersion | Should -Be '1.1'
        $document.checksumListValid | Should -BeTrue
        $document.archiveHashValid | Should -BeTrue
    }

    It 'rejects an archive traversal entry before extraction' {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipPath = Join-Path $TestDrive 'unsafe.zip'
        $stream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
        $archive = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList @($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $entry = $archive.CreateEntry('../outside.txt')
            $writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList @($entry.Open())
            try { $writer.Write('unsafe') } finally { $writer.Dispose() }
        }
        finally {
            $archive.Dispose()
            $stream.Dispose()
        }

        { Test-IncidentCapsuleIntegrity -Path $zipPath } | Should -Throw '*unsafe path segment*'
    }

    It 'verifies through the public command' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
        }
        $result = Test-IncidentCapsuleIntegrity -Path $capsuleRoot
        $result.IsValid | Should -BeTrue
        $result.SourceType | Should -Be 'Directory'
    }

    It 'rejects a manifest traversal path before accessing evidence' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
        }
        $manifestPath = Join-Path $capsuleRoot 'metadata/manifest.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.files[0].path = '../outside.txt'
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        { Test-IncidentCapsuleIntegrity -Path $capsuleRoot } | Should -Throw '*unsafe path segment*'
    }

    It 'rejects absolute manifest paths' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
        }
        $manifestPath = Join-Path $capsuleRoot 'metadata/manifest.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.files[0].path = (Join-Path $TestDrive 'outside.txt')
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        { Test-IncidentCapsuleIntegrity -Path $capsuleRoot } | Should -Throw '*must be relative*'
    }

    It 'rejects duplicate and case-colliding manifest paths' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
        }
        $manifestPath = Join-Path $capsuleRoot 'metadata/manifest.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $first = $manifest.files[0]
        $duplicate = [pscustomobject]@{
            path             = ([string]$first.path).ToUpperInvariant()
            length           = $first.length
            lastWriteTimeUtc = $first.lastWriteTimeUtc
            sha256           = $first.sha256
        }
        $manifest.files = @($manifest.files) + @($duplicate)
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        { Test-IncidentCapsuleIntegrity -Path $capsuleRoot } | Should -Throw '*duplicate or case-colliding*'
    }

    It 'rejects malformed manifest entry fields' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
        }
        $manifestPath = Join-Path $capsuleRoot 'metadata/manifest.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.files[0].sha256 = 'not-a-hash'
        $manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        { Test-IncidentCapsuleIntegrity -Path $capsuleRoot } | Should -Throw '*invalid SHA-256*'
    }

    It 'rejects reparse points while generating a manifest' -Skip:($env:OS -ne 'Windows_NT') {
        $outside = Join-Path $TestDrive 'junction-target'
        New-Item -ItemType Directory -Path $outside -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $outside 'secret.txt') -Value 'outside'
        New-Item -ItemType Junction -Path (Join-Path $capsuleRoot 'evidence/junction') -Target $outside | Out-Null

        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            $capsuleRootUnderTest = $Root
            { New-ICManifest -CapsuleRoot $capsuleRootUnderTest -CapsuleId 'IC-TEST' } | Should -Throw '*Reparse point*'
        }
    }
}

Describe 'Incident Capsule safe ZIP verification' {
    It 'rejects ZIP path traversal before extraction' {
        $archivePath = Join-Path $TestDrive 'traversal.zip'
        New-TestZipArchive -Path $archivePath -Entries @(
            [ordered]@{ Name = '../escaped.txt'; Content = 'escape' },
            [ordered]@{ Name = 'metadata/manifest.json'; Content = '{}' }
        )

        { Test-IncidentCapsuleIntegrity -Path $archivePath } | Should -Throw '*unsafe path segment*'
    }

    It 'rejects duplicate and case-colliding ZIP entries' {
        $archivePath = Join-Path $TestDrive 'duplicate.zip'
        New-TestZipArchive -Path $archivePath -Entries @(
            [ordered]@{ Name = 'evidence/item.txt'; Content = 'one' },
            [ordered]@{ Name = 'EVIDENCE/ITEM.TXT'; Content = 'two' }
        )

        { Test-IncidentCapsuleIntegrity -Path $archivePath } | Should -Throw '*duplicate or case-colliding*'
    }

    It 'enforces ZIP entry and uncompressed-size quotas' {
        $archivePath = Join-Path $TestDrive 'quota.zip'
        New-TestZipArchive -Path $archivePath -Entries @(
            [ordered]@{ Name = 'one.txt'; Content = ('a' * 64) },
            [ordered]@{ Name = 'two.txt'; Content = ('b' * 64) }
        )

        { Test-IncidentCapsuleIntegrity -Path $archivePath -MaximumArchiveEntries 1 } | Should -Throw '*entries*limit*'
        {
            Test-IncidentCapsuleIntegrity `
                -Path $archivePath `
                -MaximumArchiveEntryBytes 100 `
                -MaximumArchiveUncompressedBytes 100
        } | Should -Throw '*uncompressed size*'
    }

    It 'enforces the released per-entry expanded-size quota' {
        $archivePath = Join-Path $TestDrive 'entry-quota.zip'
        New-TestZipArchive -Path $archivePath -Entries @(
            [ordered]@{ Name = 'large.txt'; Content = ('x' * 128) }
        )

        { Test-IncidentCapsuleIntegrity -Path $archivePath -MaximumArchiveEntryBytes 32 } | Should -Throw '*per-entry size limit*'
    }

    It 'rejects ZIP entries marked as symbolic links in external attributes' {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archivePath = Join-Path $TestDrive 'symlink-metadata.zip'
        $archive = [System.IO.Compression.ZipFile]::Open($archivePath, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $archive.CreateEntry('evidence/link.txt')
            $entry.ExternalAttributes = [System.BitConverter]::ToInt32([byte[]](0x00, 0x00, 0xFF, 0xA1), 0)
            $writer = New-Object System.IO.StreamWriter($entry.Open())
            try { $writer.Write('target.txt') } finally { $writer.Dispose() }
        }
        finally {
            $archive.Dispose()
        }

        { Test-IncidentCapsuleIntegrity -Path $archivePath } | Should -Throw '*symbolic link or reparse point*'
    }

    It 'enforces the ZIP compression-ratio quota' {
        $archivePath = Join-Path $TestDrive 'ratio.zip'
        New-TestZipArchive -Path $archivePath -Entries @(
            [ordered]@{ Name = 'repeated.txt'; Content = ('0' * 10000) }
        )

        { Test-IncidentCapsuleIntegrity -Path $archivePath -MaximumArchiveCompressionRatio 2 } | Should -Throw '*compression ratio*'
    }

    It 'can require the archive sidecar' {
        $capsuleRoot = Join-Path $TestDrive 'sidecar-capsule'
        New-Item -ItemType Directory -Path (Join-Path $capsuleRoot 'metadata') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $capsuleRoot 'evidence') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $capsuleRoot 'evidence/item.txt') -Value 'content'
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-SIDECAR' | Out-Null
            New-ICArchive -CapsuleRoot $Root | Out-Null
        }
        $archivePath = "$capsuleRoot.zip"
        Remove-Item -LiteralPath "$archivePath.sha256" -Force

        { Test-IncidentCapsuleIntegrity -Path $archivePath -RequireSidecar } | Should -Throw '*Required archive sidecar*'
    }
}

Describe 'Incident Capsule archive configuration compatibility' {
    It 'requires archive limits that can verify the configured capsule and EVTX limits' {
        InModuleScope IncidentCapsule {
            $expandedTooSmall = Get-ICDefaultConfiguration -Profile Standard
            $expandedTooSmall.MaximumArchiveExpandedBytes = $expandedTooSmall.MaximumCapsuleBytes - 1
            { Test-ICConfiguration -Configuration $expandedTooSmall } | Should -Throw '*greater than or equal to MaximumCapsuleBytes*'

            $entryTooLarge = Get-ICDefaultConfiguration -Profile Standard
            $entryTooLarge.MaximumArchiveEntryBytes = $entryTooLarge.MaximumArchiveExpandedBytes + 1
            { Test-ICConfiguration -Configuration $entryTooLarge } | Should -Throw '*cannot exceed MaximumArchiveExpandedBytes*'

            $entryTooSmall = Get-ICDefaultConfiguration -Profile Standard
            $entryTooSmall.MaximumArchiveEntryBytes = $entryTooSmall.MaximumEvtxBytesPerLog - 1
            { Test-ICConfiguration -Configuration $entryTooSmall } | Should -Throw '*greater than or equal to MaximumEvtxBytesPerLog*'
        }
    }
}

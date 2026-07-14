$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

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
            { Test-ICDirectoryIntegrity -CapsuleRoot $Root } | Should -Throw '*parent-directory*'
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
            { Test-ICDirectoryIntegrity -CapsuleRoot $Root } | Should -Throw '*duplicate path*'
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

        { Test-IncidentCapsuleIntegrity -Path $zipPath } | Should -Throw '*parent-directory*'
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
}

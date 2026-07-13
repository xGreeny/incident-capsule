BeforeAll {
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1') -Force
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

    It 'verifies an unchanged directory' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $capsuleRoot } {
            param($Root)
            New-ICManifest -CapsuleRoot $Root -CapsuleId 'IC-TEST' | Out-Null
            $result = Test-ICDirectoryIntegrity -CapsuleRoot $Root
            $result.IsValid | Should -BeTrue
            $result.FilesExpected | Should -Be 2
            $result.FilesValid | Should -Be 2
            $result.FilesMissing | Should -Be 0
            $result.FilesModified | Should -Be 0
            $result.FilesUnexpected | Should -Be 0
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

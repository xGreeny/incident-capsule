$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop
$isWindowsHost = $env:OS -eq 'Windows_NT'

Describe 'Incident Capsule collection smoke test' -Skip:(-not $isWindowsHost) {
    It 'creates a valid focused directory capsule' {
        $output = Join-Path $TestDrive 'directory-capsule'
        $result = Invoke-IncidentCapsule `
            -OutputPath $output `
            -CaseId 'CI-DIRECTORY' `
            -Profile Minimal `
            -Collectors System,Processes,Services `
            -NoCompression

        $result.Status | Should -Not -Be 'Failed'
        $result.IntegrityValid | Should -BeTrue
        $result.WorkingDirectory | Should -Exist
        $result.ReportPath | Should -Exist
        $result.ManifestPath | Should -Exist
        $result.ArchivePath | Should -BeNullOrEmpty

        $verification = Test-IncidentCapsuleIntegrity -Path $result.WorkingDirectory
        $verification.IsValid | Should -BeTrue
    }

    It 'creates and verifies an archive with a sidecar checksum' {
        $output = Join-Path $TestDrive 'archive-capsule'
        $result = Invoke-IncidentCapsule `
            -OutputPath $output `
            -CaseId 'CI-ARCHIVE' `
            -Profile Minimal `
            -Collectors Processes,Services

        $result.Status | Should -Not -Be 'Failed'
        $result.IntegrityValid | Should -BeTrue
        $result.ArchivePath | Should -Exist
        $result.ArchiveChecksumPath | Should -Exist

        $verification = Test-IncidentCapsuleIntegrity -Path $result.ArchivePath
        $verification.IsValid | Should -BeTrue
        $verification.ArchiveHashValid | Should -BeTrue
        $verification.SourceType | Should -Be 'Archive'
    }
}

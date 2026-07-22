$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule capsule comparison' {
    BeforeAll {
        function New-CompareTestCapsule {
            param(
                [Parameter(Mandatory)]
                [string]$Root,

                [Parameter(Mandatory)]
                [object[]]$Services,

                [Parameter(Mandatory)]
                [string]$CapsuleId
            )

            New-Item -ItemType Directory -Path (Join-Path $Root 'metadata') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $Root 'evidence/services') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'metadata/manifest.json') -Value '{"schemaVersion":"1.3"}' -Encoding UTF8
            @{ capsule = @{ id = $CapsuleId } } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'metadata/capsule.json') -Encoding UTF8
            @{
                schemaVersion = '1.3'
                capsuleId     = $CapsuleId
                collector     = 'Services'
                capturedAtUtc = '2026-07-22T09:00:00.0000000Z'
                host          = 'TESTHOST'
                data          = $Services
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Root 'evidence/services/services.json') -Encoding UTF8
        }
    }

    It 'reports added, removed, and changed records with a stable identity' {
        $baseline = Join-Path $TestDrive 'baseline'
        $current = Join-Path $TestDrive 'current'
        New-CompareTestCapsule -Root $baseline -CapsuleId 'IC-BASE' -Services @(
            @{ Name = 'Spooler'; State = 'Running'; PathName = 'C:\Windows\System32\spoolsv.exe' },
            @{ Name = 'OldService'; State = 'Stopped'; PathName = 'C:\Legacy\old.exe' }
        )
        New-CompareTestCapsule -Root $current -CapsuleId 'IC-CURR' -Services @(
            @{ Name = 'Spooler'; State = 'Stopped'; PathName = 'C:\Windows\System32\spoolsv.exe' },
            @{ Name = 'EvilService'; State = 'Running'; PathName = 'C:\Temp\evil.exe' }
        )

        $result = Compare-IncidentCapsule -BaselinePath $baseline -CurrentPath $current

        $result.ReportPath | Should -Be "$current.comparison.json"
        $result.ReportPath | Should -Exist
        $result.BaselineCapsuleId | Should -Be 'IC-BASE'
        $result.CurrentCapsuleId | Should -Be 'IC-CURR'
        $result.TotalAdded | Should -Be 1
        $result.TotalRemoved | Should -Be 1
        $result.TotalChanged | Should -Be 1

        $services = @($result.Sections | Where-Object key -eq 'Services')[0]
        $services.comparable | Should -BeTrue
        @($services.added)[0].current.Name | Should -Be 'EvilService'
        @($services.removed)[0].baseline.Name | Should -Be 'OldService'
        $changed = @($services.changed)[0]
        @($changed.changedFields | Where-Object field -eq 'State').baseline | Should -Be 'Running'
        @($changed.changedFields | Where-Object field -eq 'State').current | Should -Be 'Stopped'
    }

    It 'marks a section not comparable when an evidence file is missing' {
        $baseline = Join-Path $TestDrive 'baseline-missing'
        $current = Join-Path $TestDrive 'current-missing'
        New-CompareTestCapsule -Root $baseline -CapsuleId 'IC-BASE2' -Services @(@{ Name = 'Spooler'; State = 'Running' })
        New-CompareTestCapsule -Root $current -CapsuleId 'IC-CURR2' -Services @(@{ Name = 'Spooler'; State = 'Running' })

        $result = Compare-IncidentCapsule -BaselinePath $baseline -CurrentPath $current

        $drivers = @($result.Sections | Where-Object key -eq 'SystemDrivers')[0]
        $drivers.comparable | Should -BeFalse
        $drivers.reason | Should -Match 'missing or unreadable'
        $result.SkippedSections | Should -BeGreaterThan 0
    }

    It 'refuses to write the report into a capsule directory' {
        $baseline = Join-Path $TestDrive 'baseline-inside'
        $current = Join-Path $TestDrive 'current-inside'
        New-CompareTestCapsule -Root $baseline -CapsuleId 'IC-BASE3' -Services @(@{ Name = 'Spooler' })
        New-CompareTestCapsule -Root $current -CapsuleId 'IC-CURR3' -Services @(@{ Name = 'Spooler' })

        { Compare-IncidentCapsule -BaselinePath $baseline -CurrentPath $current -DestinationPath (Join-Path $current 'diff.json') } |
            Should -Throw '*inside a capsule directory*'
    }
}

BeforeAll {
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1') -Force
}

Describe 'Incident Capsule derived timeline' {
    It 'creates a bounded chronological index with source references' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $TestDrive } {
            param($Root)

            $script:ICTimelineSchema = 'https://example.invalid/timeline.schema.json'
            $evidencePath = Join-Path $Root 'evidence'
            $metadataPath = Join-Path $Root 'metadata'
            New-Item -ItemType Directory -Path (Join-Path $evidencePath 'events/summaries') -Force | Out-Null
            New-Item -ItemType Directory -Path $metadataPath -Force | Out-Null

            $envelope = [ordered]@{
                collector = 'EventLogs'
                data = @(
                    [ordered]@{ TimeCreatedUtc = '2026-07-14T08:00:00Z'; Id = 1; RecordId = 11; ProviderName = 'Test'; Message = 'first' },
                    [ordered]@{ TimeCreatedUtc = '2026-07-14T09:00:00Z'; Id = 2; RecordId = 12; ProviderName = 'Test'; Message = 'second' },
                    [ordered]@{ TimeCreatedUtc = '2026-07-14T10:00:00Z'; Id = 3; RecordId = 13; ProviderName = 'Test'; Message = '=SUM(1,1)' },
                    [ordered]@{ TimeCreatedUtc = 'not-a-timestamp'; Id = 4; RecordId = 14; ProviderName = 'Test'; Message = 'invalid' }
                )
            }
            [void](Write-ICJsonFile -Path (Join-Path $evidencePath 'events/summaries/test.json') -InputObject $envelope)
            [void](Write-ICUtf8File -Path (Join-Path $evidencePath 'events/summaries/broken.json') -Content '{')

            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.MaximumTimelineEntries = 2
            $context = [pscustomobject]@{
                CapsuleId = 'IC-TIMELINE'
                RootPath = $Root
                EvidencePath = $evidencePath
                MetadataPath = $metadataPath
                Configuration = $configuration
            }

            $result = New-ICTimelineIndex -Context $context

            $result.CandidateCount | Should -Be 3
            $result.EntryCount | Should -Be 2
            $result.Truncated | Should -BeTrue
            $result.SourceFiles | Should -Be 2
            $result.SourceFilesRead | Should -Be 1
            $result.SourceFilesFailed | Should -Be 1
            $result.InvalidTimestampCount | Should -Be 1
            $result.Entries[0].title | Should -Be 'second'
            $result.Entries[1].title | Should -Be '=SUM(1,1)'
            $result.Entries[0].source | Should -Be 'evidence/events/summaries/test.json'
            $result.Entries[0].sourceIndex | Should -Be 1
            $result.Entries[1].sourceIndex | Should -Be 2
            $result.JsonPath | Should -Exist
            $result.CsvPath | Should -Exist

            $timelineJson = Get-Content -LiteralPath $result.JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $timelineJson.schemaVersion | Should -Be $script:ICSchemaVersion
            @($timelineJson.entries).Count | Should -Be 2
            $timelineJson.entries[1].title | Should -Be '=SUM(1,1)'
            (Get-Content -LiteralPath $result.CsvPath -Raw -Encoding UTF8) | Should -Match "'=SUM\(1,1\)"
        }
    }

    It 'writes an empty, valid timeline when no timestamped evidence exists' {
        InModuleScope IncidentCapsule -Parameters @{ Root = $TestDrive } {
            param($Root)

            $emptyRoot = Join-Path $Root 'empty-capsule'
            $evidencePath = Join-Path $emptyRoot 'evidence'
            New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null

            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.MaximumTimelineEntries = 1
            $context = [pscustomobject]@{
                CapsuleId = 'IC-EMPTY-TIMELINE'
                RootPath = $emptyRoot
                EvidencePath = $evidencePath
                Configuration = $configuration
            }

            $result = New-ICTimelineIndex -Context $context

            $result.SourceFiles | Should -Be 0
            $result.CandidateCount | Should -Be 0
            $result.EntryCount | Should -Be 0
            $result.Truncated | Should -BeFalse
            @($result.Entries).Count | Should -Be 0
            $result.JsonPath | Should -Exist
            $result.CsvPath | Should -Exist
        }
    }

    It 'encodes safe local report links and rejects path escapes' {
        InModuleScope IncidentCapsule {
            ConvertTo-ICReportHref -RelativePath 'evidence/events/a b#c.json' |
                Should -Be '../evidence/events/a%20b%23c.json'
            ConvertTo-ICReportHref -RelativePath '../outside.json' | Should -BeNullOrEmpty
            ConvertTo-ICReportHref -RelativePath '/absolute.json' | Should -BeNullOrEmpty
            ConvertTo-ICReportHref -RelativePath 'C:\outside.json' | Should -BeNullOrEmpty
        }
    }
}

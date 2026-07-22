$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule JSONL export' {
    BeforeAll {
        function New-ExportTestCapsule {
            param(
                [Parameter(Mandatory)]
                [string]$Root
            )

            New-Item -ItemType Directory -Path (Join-Path $Root 'metadata') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $Root 'evidence/processes') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $Root 'evidence/services') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'metadata/manifest.json') -Value '{"schemaVersion":"1.2"}' -Encoding UTF8

            $processes = @{
                schemaVersion = '1.2'
                capsuleId     = 'IC-EXPORT'
                collector     = 'Processes'
                capturedAtUtc = '2026-07-22T08:00:00.0000000Z'
                host          = 'TESTHOST'
                data          = @(
                    @{ ProcessId = 4; Name = 'System' },
                    @{ ProcessId = 1234; Name = 'example.exe' }
                )
            } | ConvertTo-Json -Depth 5
            Set-Content -LiteralPath (Join-Path $Root 'evidence/processes/processes.json') -Value $processes -Encoding UTF8

            $services = @{
                schemaVersion = '1.2'
                capsuleId     = 'IC-EXPORT'
                collector     = 'Services'
                capturedAtUtc = '2026-07-22T08:00:01.0000000Z'
                host          = 'TESTHOST'
                data          = @{ Name = 'Spooler'; State = 'Running' }
            } | ConvertTo-Json -Depth 5
            Set-Content -LiteralPath (Join-Path $Root 'evidence/services/services.json') -Value $services -Encoding UTF8

            Set-Content -LiteralPath (Join-Path $Root 'evidence/services/notes.json') -Value '{"unrelated":true}' -Encoding UTF8
        }
    }

    It 'exports one line per evidence record with envelope context' {
        $root = Join-Path $TestDrive 'export-basic'
        New-ExportTestCapsule -Root $root

        $result = Export-IncidentCapsuleData -Path $root

        $result.Path | Should -Be "$root.evidence.jsonl"
        $result.Path | Should -Exist
        $result.EnvelopeCount | Should -Be 2
        $result.RecordCount | Should -Be 3
        $result.SkippedFiles | Should -Be @('evidence/services/notes.json')
        $result.Collectors | Should -Be @('Processes', 'Services')

        $lines = @(Get-Content -LiteralPath $result.Path)
        $lines.Count | Should -Be 3
        $first = $lines[0] | ConvertFrom-Json
        $first.capsuleId | Should -Be 'IC-EXPORT'
        $first.host | Should -Be 'TESTHOST'
        $first.collector | Should -Be 'Processes'
        $first.source | Should -Be 'evidence/processes/processes.json'
        $first.recordIndex | Should -Be 0
        $first.record.ProcessId | Should -Be 4
    }

    It 'filters exported envelopes by collector' {
        $root = Join-Path $TestDrive 'export-filtered'
        New-ExportTestCapsule -Root $root

        $result = Export-IncidentCapsuleData -Path $root -Collector Services

        $result.EnvelopeCount | Should -Be 1
        $result.RecordCount | Should -Be 1
        $result.Collectors | Should -Be @('Services')
        (Get-Content -LiteralPath $result.Path | Select-Object -First 1 | ConvertFrom-Json).record.Name | Should -Be 'Spooler'
    }

    It 'refuses to write into the capsule directory' {
        $root = Join-Path $TestDrive 'export-inside'
        New-ExportTestCapsule -Root $root

        { Export-IncidentCapsuleData -Path $root -DestinationPath (Join-Path $root 'export.jsonl') } | Should -Throw '*inside the capsule directory*'
    }

    It 'refuses to overwrite an existing destination' {
        $root = Join-Path $TestDrive 'export-existing'
        New-ExportTestCapsule -Root $root
        $destination = Join-Path $TestDrive 'existing.jsonl'
        Set-Content -LiteralPath $destination -Value 'occupied' -Encoding UTF8

        { Export-IncidentCapsuleData -Path $root -DestinationPath $destination } | Should -Throw '*already exists*'
    }
}

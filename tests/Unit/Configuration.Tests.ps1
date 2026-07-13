$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule configuration' {
    InModuleScope IncidentCapsule {
        It 'returns an independent default configuration object' {
            $first = Get-ICDefaultConfiguration -Profile Standard
            $second = Get-ICDefaultConfiguration -Profile Standard
            $first.Collectors = @('System')
            $second.Collectors.Count | Should -BeGreaterThan 1
        }

        It 'replaces scalar and array values during merge' {
            $base = Get-ICDefaultConfiguration -Profile Standard
            $override = @{
                EventLookbackHours = 6
                Collectors = @('System', 'Processes')
            }
            $merged = Merge-ICHashtable -Base $base -Override $override
            $merged.EventLookbackHours | Should -Be 6
            $merged.Collectors | Should -Be @('System', 'Processes')
            $base.EventLookbackHours | Should -Be 24
        }

        It 'rejects unknown configuration keys' {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration['UnknownSetting'] = $true
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw '*Unknown configuration key*'
        }

        It 'rejects an unknown collector' {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.Collectors = @('System', 'ImaginaryCollector')
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw '*Unknown collector*'
        }

        It 'rejects invalid numeric bounds' {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.MaximumEventsPerLog = 0
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw '*greater than zero*'
        }

        It 'applies explicit collectors before exclusions' {
            $configuration = Resolve-ICConfiguration -Profile Standard -Collectors @('System', 'Processes', 'Network') -ExcludeCollector @('Network')
            $configuration.Collectors | Should -Be @('System', 'Processes')
        }
    }

    It 'loads safe PSD1 overrides' {
        $path = Join-Path $TestDrive 'override.psd1'
        "@{ EventLookbackHours = 8; ExportEvtx = `$false }" | Set-Content -LiteralPath $path -Encoding UTF8
        InModuleScope IncidentCapsule -Parameters @{ ConfigurationPath = $path } {
            param($ConfigurationPath)
            $configuration = Resolve-ICConfiguration -Profile Standard -ConfigurationPath $ConfigurationPath
            $configuration.EventLookbackHours | Should -Be 8
            $configuration.ExportEvtx | Should -BeFalse
            $configuration.Collectors.Count | Should -BeGreaterThan 1
        }
    }
}

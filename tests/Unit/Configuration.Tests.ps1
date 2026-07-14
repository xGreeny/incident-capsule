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
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw '*must be between*'
        }

        It 'provides bounded resource defaults for every profile' {
            $minimal = Get-ICDefaultConfiguration -Profile Minimal
            $standard = Get-ICDefaultConfiguration -Profile Standard
            $extended = Get-ICDefaultConfiguration -Profile Extended

            $minimal.MaximumCapsuleBytes | Should -Be 1073741824
            $standard.MaximumCapsuleBytes | Should -Be 5368709120
            $extended.MaximumCapsuleBytes | Should -Be 21474836480
            @($minimal.MaximumTimelineEntries, $standard.MaximumTimelineEntries, $extended.MaximumTimelineEntries) | Should -Be @(2000, 10000, 50000)
            @($minimal.NativeCommandTimeoutSeconds, $standard.NativeCommandTimeoutSeconds, $extended.NativeCommandTimeoutSeconds) | Should -Be @(30, 60, 120)
        }

        It 'rejects resource budgets above their hard maxima' {
            $configuration = Get-ICDefaultConfiguration -Profile Standard
            $configuration.NativeCommandTimeoutSeconds = 901
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw "*'NativeCommandTimeoutSeconds'*between*900*"
        }

        It 'rejects unsupported data handling profiles' {
            $configuration = Get-ICDefaultConfiguration -Profile Standard
            $configuration.DataHandlingProfile = 'Aggressive'
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw "*DataHandlingProfile*Full*Minimized*"
        }

        It 'uses privacy-conscious defaults for the Minimal profile' {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.DataHandlingProfile | Should -Be 'Minimized'
            $configuration.IncludeProcessCommandLines | Should -BeFalse
            $configuration.ExportScheduledTaskXml | Should -BeFalse
            $configuration.CollectDefenderPreferences | Should -BeFalse
            $configuration.CollectWindowsUpdateHistory | Should -BeFalse
        }


        It 'rejects values above hard collection limits' {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.MaximumEventsPerLog = 100001
            { Test-ICConfiguration -Configuration $configuration } | Should -Throw '*supported maximum*'
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

    It 'applies Minimized handling while preserving explicit sensitive overrides' {
        $path = Join-Path $TestDrive 'minimized.psd1'
        "@{ DataHandlingProfile = 'Minimized'; IncludeProcessCommandLines = `$true }" | Set-Content -LiteralPath $path -Encoding UTF8
        InModuleScope IncidentCapsule -Parameters @{ ConfigurationPath = $path } {
            param($ConfigurationPath)
            $configuration = Resolve-ICConfiguration -Profile Standard -ConfigurationPath $ConfigurationPath
            $configuration.DataHandlingProfile | Should -Be 'Minimized'
            $configuration.IncludeProcessCommandLines | Should -BeTrue
            $configuration.ExportScheduledTaskXml | Should -BeFalse
            $configuration.CollectDefenderPreferences | Should -BeFalse
            $configuration.CollectWindowsUpdateHistory | Should -BeFalse
        }
    }
}

BeforeAll {
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
    Import-Module $moduleManifest -Force -ErrorAction Stop
}

Describe 'Incident Capsule readiness' {
    It 'returns Ready with the complete effective configuration when all checks pass' {
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $TestDrive } {
            param($OutputPath)
            Mock Test-ICWindows { $true }
            Mock Test-ICAdministrator { $true }
            Mock Get-ICAvailableStorageByte { 1099511627776L }
            Mock Get-ICCommandReadinessCheck { @() }
            Mock Get-ICCimReadinessCheck { @() }
            Mock Get-ICEventLogReadinessCheck { @() }

            $result = Test-IncidentCapsuleReadiness -OutputPath $OutputPath -Profile Minimal -Collectors System -NoCompression

            $result.Status | Should -Be 'Ready'
            $result.IsReady | Should -BeTrue
            $result.Configuration.Keys | Should -Be $script:ICConfigurationKeys
            $result.Configuration.Collectors | Should -Be @('System')
            $result.CompressionEnabled | Should -BeFalse
            @($result.Checks.Code) | Should -Contain 'DISK_SPACE_SUFFICIENT'
            ($result.Checks | Where-Object Code -eq 'DISK_SPACE_SUFFICIENT').Details.ArchiveHeadroomBytes | Should -Be 0
        }
    }

    It 'blocks a non-Windows host with a stable reason code' {
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $TestDrive } {
            param($OutputPath)
            Mock Test-ICWindows { $false }
            Mock Get-ICAvailableStorageByte { 1099511627776L }

            $result = Test-IncidentCapsuleReadiness -OutputPath $OutputPath -Profile Minimal -Collectors System -NoCompression

            $result.Status | Should -Be 'Blocked'
            $result.IsReady | Should -BeFalse
            @($result.Checks.Code) | Should -Contain 'WINDOWS_REQUIRED'
            ($result.Checks | Where-Object Code -eq 'WINDOWS_REQUIRED').Severity | Should -Be 'Error'
        }
    }

    It 'reports a non-elevated host as ReadyWithWarnings' {
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $TestDrive } {
            param($OutputPath)
            Mock Test-ICWindows { $true }
            Mock Test-ICAdministrator { $false }
            Mock Get-ICAvailableStorageByte { 1099511627776L }
            Mock Get-ICCommandReadinessCheck { @() }
            Mock Get-ICCimReadinessCheck { @() }
            Mock Get-ICEventLogReadinessCheck { @() }

            $result = Test-IncidentCapsuleReadiness -OutputPath $OutputPath -Profile Minimal -Collectors System -NoCompression

            $result.Status | Should -Be 'ReadyWithWarnings'
            $result.IsReady | Should -BeTrue
            @($result.Checks.Code) | Should -Contain 'NOT_ELEVATED'
        }
    }

    It 'blocks when free space does not cover capsule and ZIP headroom' {
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $TestDrive } {
            param($OutputPath)
            Mock Test-ICWindows { $true }
            Mock Test-ICAdministrator { $true }
            Mock Get-ICAvailableStorageByte { 1073741824L }
            Mock Get-ICCommandReadinessCheck { @() }
            Mock Get-ICCimReadinessCheck { @() }
            Mock Get-ICEventLogReadinessCheck { @() }

            $result = Test-IncidentCapsuleReadiness -OutputPath $OutputPath -Profile Minimal -Collectors System
            $spaceCheck = $result.Checks | Where-Object Code -eq 'INSUFFICIENT_SPACE'

            $result.Status | Should -Be 'Blocked'
            $spaceCheck.Details.RequiredBytes | Should -Be 2147483648
            $spaceCheck.Details.ArchiveHeadroomBytes | Should -Be 1073741824
        }
    }

    It 'does not leave its writability probe behind' {
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $TestDrive } {
            param($OutputPath)
            $before = @(Get-ChildItem -LiteralPath $OutputPath -Force).Count
            $result = Test-ICOutputWritable -Path $OutputPath
            $after = @(Get-ChildItem -LiteralPath $OutputPath -Force).Count

            $result.IsWritable | Should -BeTrue
            $after | Should -Be $before
        }
    }

    It 'uses stable event channel codes for ready, disabled, and unavailable channels' {
        InModuleScope IncidentCapsule {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.Collectors = @('EventLogs')
            $configuration.EventLogs = @('ReadyLog', 'DisabledLog', 'MissingLog')

            Mock Get-Command { [pscustomobject]@{ Name = 'Get-WinEvent' } } -ParameterFilter { $Name -eq 'Get-WinEvent' }
            Mock Get-WinEvent {
                if ($ListLog -eq 'ReadyLog') {
                    return [pscustomobject]@{ LogName = $ListLog; IsEnabled = $true }
                }
                if ($ListLog -eq 'DisabledLog') {
                    return [pscustomobject]@{ LogName = $ListLog; IsEnabled = $false }
                }
                if ($ListLog -eq 'MissingLog') {
                    throw 'The specified channel could not be found.'
                }
            }

            $checks = @(Get-ICEventLogReadinessCheck -Configuration $configuration)

            ($checks | Where-Object { $_.Details.EventLog -eq 'ReadyLog' }).Code | Should -Be 'EVENT_LOG_READY'
            ($checks | Where-Object { $_.Details.EventLog -eq 'DisabledLog' }).Code | Should -Be 'EVENT_LOG_DISABLED'
            ($checks | Where-Object { $_.Details.EventLog -eq 'MissingLog' }).Code | Should -Be 'EVENT_LOG_UNAVAILABLE'
        }
    }
}

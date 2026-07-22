$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule event-log collector' -Skip:($env:OS -ne 'Windows_NT') {
    It 'truncates over-long event messages and counts them' {
        $rootPath = Join-Path $TestDrive 'eventlogs-truncate'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.EventLogs = @('System')
            $configuration.MaximumEventsPerLog = 25
            $configuration.MaximumEventMessageChars = 256
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-EVENTS'
                HostName         = $env:COMPUTERNAME
                Configuration    = $configuration
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $result = Invoke-ICCollector -Context $context -Name EventLogs

            $result.status | Should -BeIn @('Succeeded', 'Partial')
            $result.metrics.MaximumEventMessageChars | Should -Be 256
            $result.metrics.Keys | Should -Contain 'TruncatedMessages'
            $summaryFile = @(Get-ChildItem -LiteralPath (Join-Path $RootPath 'evidence/events/summaries') -Filter 'System-*.json' -ErrorAction SilentlyContinue)[0]
            $summaryFile | Should -Not -BeNullOrEmpty
            $data = (Get-Content -LiteralPath $summaryFile.FullName -Raw | ConvertFrom-Json).data
            foreach ($decoded in @($data)) {
                if ($decoded.MessageTruncated) {
                    ([string]$decoded.Message).Length | Should -BeLessOrEqual (256 + 40)
                }
            }
        }
    }

    It 'treats an absent optional channel as non-partial coverage' {
        $rootPath = Join-Path $TestDrive 'eventlogs-optional'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            # A channel that is optional and (on the CI host) absent must not warn.
            $configuration.EventLogs = @('Microsoft-Windows-Sysmon/Operational')
            $configuration.ExportEvtx = $false
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-EVENTS'
                HostName         = $env:COMPUTERNAME
                Configuration    = $configuration
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $sysmonPresent = $null -ne (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
            $result = Invoke-ICCollector -Context $context -Name EventLogs

            if (-not $sysmonPresent) {
                $result.status | Should -Be 'Succeeded'
                @($result.warnings).Count | Should -Be 0
                $result.metrics.OptionalChannelsMissing | Should -Be 1
            }
        }
    }

    It 'marks optional missing channels as information in readiness checks' {
        InModuleScope IncidentCapsule {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.EventLogs = @('Microsoft-Windows-Sysmon/Operational')
            $checks = @(Get-ICEventLogReadinessCheck -Configuration $configuration)
            $sysmonPresent = $null -ne (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
            if (-not $sysmonPresent) {
                $sysmonCheck = @($checks | Where-Object { $_.Details.EventLog -eq 'Microsoft-Windows-Sysmon/Operational' })[0]
                $sysmonCheck.Code | Should -Be 'EVENT_LOG_OPTIONAL_ABSENT'
                $sysmonCheck.Status | Should -Be 'Passed'
                $sysmonCheck.Severity | Should -Be 'Information'
            }
        }
    }
}

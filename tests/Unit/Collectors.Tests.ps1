$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule v1.2 collectors' -Skip:($env:OS -ne 'Windows_NT') {
    It 'collects an installed-software inventory' {
        $rootPath = Join-Path $TestDrive 'collector-software'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-COLLECTOR'
                HostName         = $env:COMPUTERNAME
                Configuration    = Get-ICDefaultConfiguration -Profile Standard
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $result = Invoke-ICCollector -Context $context -Name InstalledSoftware

            $result.status | Should -BeIn @('Succeeded', 'Partial')
            $result.outputFiles | Should -Contain 'evidence/software/installed-software.json'
            $envelope = Get-Content -LiteralPath (Join-Path $RootPath 'evidence/software/installed-software.json') -Raw | ConvertFrom-Json
            $envelope.collector | Should -Be 'InstalledSoftware'
            $envelope.schemaVersion | Should -Be '1.2'
            @($envelope.data).Count | Should -BeGreaterThan 0
        }
    }

    It 'collects the local-machine certificate stores' {
        $rootPath = Join-Path $TestDrive 'collector-certificates'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-COLLECTOR'
                HostName         = $env:COMPUTERNAME
                Configuration    = Get-ICDefaultConfiguration -Profile Standard
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $result = Invoke-ICCollector -Context $context -Name Certificates

            $result.status | Should -BeIn @('Succeeded', 'Partial')
            $result.outputFiles | Should -Contain 'evidence/certificates/certificate-stores.json'
            $envelope = Get-Content -LiteralPath (Join-Path $RootPath 'evidence/certificates/certificate-stores.json') -Raw | ConvertFrom-Json
            @($envelope.data).Count | Should -BeGreaterThan 0
            $entry = @($envelope.data)[0]
            $entry.Thumbprint | Should -Not -BeNullOrEmpty
            $entry.PSObject.Properties.Name | Should -Not -Contain 'RawData'
        }
    }

    It 'collects execution artifacts without failing on restricted sources' {
        $rootPath = Join-Path $TestDrive 'collector-execution'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-COLLECTOR'
                HostName         = $env:COMPUTERNAME
                Configuration    = Get-ICDefaultConfiguration -Profile Standard
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $result = Invoke-ICCollector -Context $context -Name ExecutionArtifacts

            $result.status | Should -BeIn @('Succeeded', 'Partial')
            $result.outputFiles | Should -Contain 'evidence/execution/prefetch-files.json'
            $result.outputFiles | Should -Contain 'evidence/execution/bam-entries.json'
            $result.outputFiles | Should -Contain 'evidence/execution/userassist-entries.json'
            $result.metrics.Keys | Should -Contain 'PrefetchFilesCopied'
        }
    }

    It 'collects device history and bounds the setup log copy' {
        $rootPath = Join-Path $TestDrive 'collector-devices'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-COLLECTOR'
                HostName         = $env:COMPUTERNAME
                Configuration    = Get-ICDefaultConfiguration -Profile Standard
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $result = Invoke-ICCollector -Context $context -Name Devices

            $result.status | Should -BeIn @('Succeeded', 'Partial')
            $result.outputFiles | Should -Contain 'evidence/devices/usb-storage.json'
            $result.outputFiles | Should -Contain 'evidence/devices/mounted-devices.json'
            $result.outputFiles | Should -Contain 'evidence/devices/setupapi-log.json'
            $envelope = Get-Content -LiteralPath (Join-Path $RootPath 'evidence/devices/mounted-devices.json') -Raw | ConvertFrom-Json
            $envelope.collector | Should -Be 'Devices'
        }
    }
}


Describe 'Incident Capsule collector stability regressions' -Skip:($env:OS -ne 'Windows_NT') {
    It 'collects <Name> without a terminating failure in the current edition' -ForEach @(
        @{ Name = 'System' },
        @{ Name = 'ScheduledTasks' },
        @{ Name = 'Sessions' }
    ) {
        $rootPath = Join-Path $TestDrive "regression-$Name"
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath; CollectorName = $Name } {
            param($RootPath, $CollectorName)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CapsuleId        = 'IC-REGRESSION'
                HostName         = $env:COMPUTERNAME
                IsElevated       = Test-ICAdministrator
                Configuration    = Get-ICDefaultConfiguration -Profile Minimal
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $result = Invoke-ICCollector -Context $context -Name $CollectorName

            $result.status | Should -BeIn @('Succeeded', 'Partial')
            @($result.outputFiles).Count | Should -BeGreaterThan 0
        }
    }
}

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule collector resource budget' {
    It 'records remaining collectors as skipped after the capsule byte limit is reached' {
        $rootPath = Join-Path $TestDrive 'budget-capsule'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            Write-ICUtf8File -Path (Join-Path $RootPath 'already-full.bin') -Content 'over-budget' | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                Configuration    = [ordered]@{
                    Collectors          = @('System', 'Processes')
                    MaximumCapsuleBytes = 1L
                }
                CollectorResults = New-Object System.Collections.ArrayList
            }

            $results = @(Invoke-ICCollectors -Context $context)

            $results.Count | Should -Be 2
            @($results.status) | Should -Be @('Skipped', 'Skipped')
            @($results.issues.code) | Should -Be @('LIMIT_REACHED', 'LIMIT_REACHED')
            Get-ICOverallStatus -CollectorResults $results -FatalError $null | Should -Be 'CompletedWithWarnings'
        }
    }
}

Describe 'Incident Capsule collector engine' {
    It 'records a terminating collector failure without throwing' {
        $rootPath = Join-Path $TestDrive 'engine-failure'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CollectorResults = New-Object System.Collections.ArrayList
            }
            Mock Get-ICSystemEvidence { throw 'source unavailable' }

            $result = Invoke-ICCollector -Context $context -Name System

            $result.status | Should -Be 'Failed'
            $result.error | Should -Be 'source unavailable'
            $result.outputFiles | Should -BeNullOrEmpty
            @($context.CollectorResults).Count | Should -Be 1
            Get-Content -LiteralPath $context.LogPath -Raw | Should -Match 'source unavailable'
        }
    }

    It 'marks a collector with warnings as partial and logs the warning' {
        $rootPath = Join-Path $TestDrive 'engine-partial'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CollectorResults = New-Object System.Collections.ArrayList
            }
            Mock Get-ICSystemEvidence { New-ICCollectorResultData -Warnings @('channel unavailable') }

            $result = Invoke-ICCollector -Context $context -Name System

            $result.status | Should -Be 'Partial'
            $result.warnings | Should -Contain 'channel unavailable'
            Get-Content -LiteralPath $context.LogPath -Raw | Should -Match 'channel unavailable'
        }
    }

    It 'treats a missing collector result object as partial' {
        $rootPath = Join-Path $TestDrive 'engine-null-result'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CollectorResults = New-Object System.Collections.ArrayList
            }
            Mock Get-ICSystemEvidence { $null }

            $result = Invoke-ICCollector -Context $context -Name System

            $result.status | Should -Be 'Partial'
            $result.warnings | Should -Contain 'Collector returned no result object.'
        }
    }

    It 'keeps relative forward-slash paths for files inside the capsule root' {
        $rootPath = Join-Path $TestDrive 'engine-inside'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CollectorResults = New-Object System.Collections.ArrayList
            }
            Mock Get-ICSystemEvidence {
                New-ICCollectorResultData -OutputFiles @(
                    (Join-Path $Context.RootPath 'evidence\system\system.json')
                )
            }

            $result = Invoke-ICCollector -Context $context -Name System

            $result.status | Should -Be 'Succeeded'
            $result.outputFiles | Should -Be @('evidence/system/system.json')
        }
    }

    It 'flags and logs an output file outside the capsule root' {
        $rootPath = Join-Path $TestDrive 'engine-outside'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CollectorResults = New-Object System.Collections.ArrayList
            }
            Mock Get-ICSystemEvidence {
                New-ICCollectorResultData -OutputFiles @(
                    [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'ic-outside.txt')
                )
            }

            $result = Invoke-ICCollector -Context $context -Name System

            $result.status | Should -Be 'Partial'
            $result.outputFiles | Should -BeNullOrEmpty
            @($result.warnings).Count | Should -Be 1
            $result.warnings[0] | Should -Match 'outside the capsule root'
            Get-Content -LiteralPath $context.LogPath -Raw | Should -Match 'outside the capsule root'
        }
    }

    It 'rejects an unregistered collector name' {
        $rootPath = Join-Path $TestDrive 'engine-unregistered'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            New-Item -ItemType Directory -Path (Join-Path $RootPath 'logs') -Force | Out-Null
            $context = [pscustomobject]@{
                RootPath         = $RootPath
                LogPath          = Join-Path $RootPath 'logs/collector.log'
                Frozen           = $false
                CollectorResults = New-Object System.Collections.ArrayList
            }

            { Invoke-ICCollector -Context $context -Name 'DoesNotExist' } | Should -Throw '*not registered*'
        }
    }
}

Describe 'Incident Capsule overall status' {
    It 'computes Completed for an empty collector result set' {
        InModuleScope IncidentCapsule {
            Get-ICOverallStatus -CollectorResults @() -FatalError $null | Should -Be 'Completed'
        }
    }

    It 'prioritizes a fatal error over collector states' {
        InModuleScope IncidentCapsule {
            $results = @([pscustomobject]@{ status = 'Succeeded' })
            Get-ICOverallStatus -CollectorResults $results -FatalError 'disk full' | Should -Be 'Failed'
        }
    }

    It 'reports errors over warnings' {
        InModuleScope IncidentCapsule {
            $results = @(
                [pscustomobject]@{ status = 'Succeeded' },
                [pscustomobject]@{ status = 'Partial' },
                [pscustomobject]@{ status = 'Failed' }
            )
            Get-ICOverallStatus -CollectorResults $results -FatalError $null | Should -Be 'CompletedWithErrors'
        }
    }

    It 'reports warnings when only partial results exist' {
        InModuleScope IncidentCapsule {
            $results = @(
                [pscustomobject]@{ status = 'Succeeded' },
                [pscustomobject]@{ status = 'Partial' }
            )
            Get-ICOverallStatus -CollectorResults $results -FatalError $null | Should -Be 'CompletedWithWarnings'
        }
    }
}

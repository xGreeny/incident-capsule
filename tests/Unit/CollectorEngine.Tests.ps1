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

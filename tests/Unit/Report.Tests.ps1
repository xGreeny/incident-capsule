$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule report generation' {
    It 'renders a complete report when no collector result exists' {
        $rootPath = Join-Path $TestDrive 'report-empty'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            $context = [pscustomobject]@{
                CapsuleId        = 'IC-TEST'
                CaseId           = 'IR-TEST-0001'
                Operator         = 'tester'
                Profile          = 'Minimal'
                HostName         = 'TESTHOST'
                IsElevated       = $false
                Status           = 'Completed'
                StartedAtUtc     = [datetime]::UtcNow.AddMinutes(-1)
                CompletedAtUtc   = [datetime]::UtcNow
                MetadataPath     = Join-Path $RootPath 'metadata'
                ReportPath       = Join-Path $RootPath 'report/index.html'
                CollectorResults = New-Object System.Collections.ArrayList
                Coverage         = [pscustomobject]@{
                    collectors     = @()
                    issues         = @()
                    privacyScope   = [ordered]@{ commandLines = 'included' }
                    resourceLimits = [ordered]@{ maximumCapsuleBytes = 1048576 }
                }
            }

            $path = New-ICHtmlReport -Context $context

            $path | Should -Exist
            $html = Get-Content -LiteralPath $path -Raw
            $html | Should -Match 'No scalar metrics were reported\.'
            $html | Should -Match 'No collector warning or fatal error was recorded\.'
            $html | Should -Match 'Timeline index was not generated\.'
            $html | Should -Match 'Machine-readable coverage was not written\.'
        }
    }

    It 'returns no rows for an empty metric set' {
        InModuleScope IncidentCapsule {
            ConvertTo-ICMetricRows -CollectorResults @() | Should -BeNullOrEmpty
        }
    }

    It 'HTML-encodes evidence-derived values' {
        $rootPath = Join-Path $TestDrive 'report-encoding'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            $malicious = '<script>alert(1)</script>'
            $results = New-Object System.Collections.ArrayList
            [void]$results.Add([pscustomobject][ordered]@{
                name                 = 'System'
                status               = 'Partial'
                durationMilliseconds = 1234
                outputFiles          = @()
                warnings             = @($malicious)
                error                = ''
                metrics              = [ordered]@{}
            })
            $context = [pscustomobject]@{
                CapsuleId        = 'IC-TEST'
                CaseId           = 'IR-TEST-0001'
                Operator         = 'tester'
                Profile          = 'Minimal'
                HostName         = 'TESTHOST'
                IsElevated       = $false
                Status           = 'CompletedWithWarnings'
                StartedAtUtc     = [datetime]::UtcNow.AddMinutes(-1)
                CompletedAtUtc   = [datetime]::UtcNow
                MetadataPath     = Join-Path $RootPath 'metadata'
                ReportPath       = Join-Path $RootPath 'report/index.html'
                CollectorResults = $results
                Coverage         = [pscustomobject]@{
                    collectors     = @()
                    issues         = @()
                    privacyScope   = [ordered]@{ commandLines = 'included' }
                    resourceLimits = [ordered]@{ maximumCapsuleBytes = 1048576 }
                }
            }

            $html = Get-Content -LiteralPath (New-ICHtmlReport -Context $context) -Raw

            $html | Should -Not -Match ([regex]::Escape($malicious))
            $html | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
        }
    }

    It 'renders scalar metrics and skips collection values' {
        $rootPath = Join-Path $TestDrive 'report-metrics'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            $results = New-Object System.Collections.ArrayList
            [void]$results.Add([pscustomobject][ordered]@{
                name                 = 'System'
                status               = 'Succeeded'
                durationMilliseconds = 1234
                outputFiles          = @()
                warnings             = @()
                error                = ''
                metrics              = [ordered]@{ ProcessCount = 42; Ignored = @(1, 2) }
            })
            $context = [pscustomobject]@{
                CapsuleId        = 'IC-TEST'
                CaseId           = 'IR-TEST-0001'
                Operator         = 'tester'
                Profile          = 'Minimal'
                HostName         = 'TESTHOST'
                IsElevated       = $false
                Status           = 'Completed'
                StartedAtUtc     = [datetime]::UtcNow.AddMinutes(-1)
                CompletedAtUtc   = [datetime]::UtcNow
                MetadataPath     = Join-Path $RootPath 'metadata'
                ReportPath       = Join-Path $RootPath 'report/index.html'
                CollectorResults = $results
                Coverage         = [pscustomobject]@{
                    collectors     = @()
                    issues         = @()
                    privacyScope   = [ordered]@{ commandLines = 'included' }
                    resourceLimits = [ordered]@{ maximumCapsuleBytes = 1048576 }
                }
            }

            $html = Get-Content -LiteralPath (New-ICHtmlReport -Context $context) -Raw

            $html | Should -Match '<td>ProcessCount</td><td>42</td>'
            $html | Should -Not -Match '<td>Ignored</td>'
        }
    }

    It 'lists a collector error and omits unsafe evidence links' {
        $rootPath = Join-Path $TestDrive 'report-error'
        InModuleScope IncidentCapsule -Parameters @{ RootPath = $rootPath } {
            param($RootPath)

            $results = New-Object System.Collections.ArrayList
            [void]$results.Add([pscustomobject][ordered]@{
                name                 = 'System'
                status               = 'Failed'
                durationMilliseconds = 1234
                outputFiles          = @('../../escape.txt')
                warnings             = @()
                error                = 'access denied'
                metrics              = [ordered]@{}
            })
            $context = [pscustomobject]@{
                CapsuleId        = 'IC-TEST'
                CaseId           = 'IR-TEST-0001'
                Operator         = 'tester'
                Profile          = 'Minimal'
                HostName         = 'TESTHOST'
                IsElevated       = $false
                Status           = 'CompletedWithErrors'
                StartedAtUtc     = [datetime]::UtcNow.AddMinutes(-1)
                CompletedAtUtc   = [datetime]::UtcNow
                MetadataPath     = Join-Path $RootPath 'metadata'
                ReportPath       = Join-Path $RootPath 'report/index.html'
                CollectorResults = $results
                Coverage         = [pscustomobject]@{
                    collectors     = @()
                    issues         = @()
                    privacyScope   = [ordered]@{ commandLines = 'included' }
                    resourceLimits = [ordered]@{ maximumCapsuleBytes = 1048576 }
                }
            }

            $html = Get-Content -LiteralPath (New-ICHtmlReport -Context $context) -Raw

            $html | Should -Match 'access denied'
            $html | Should -Match 'Unsafe output path omitted'
            $html | Should -Not -Match 'href="\.\./\.\./escape\.txt"'
        }
    }
}

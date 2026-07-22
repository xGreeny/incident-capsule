BeforeAll {
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1') -Force
}

Describe 'Incident Capsule structured coverage' {
    It 'maps collector warnings to stable issue codes and preserves coverage state' {
        InModuleScope IncidentCapsule {
            $script:ICCoverageSchema = 'https://example.invalid/coverage.schema.json'
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.Collectors = @('System', 'EventLogs')
            $results = New-Object System.Collections.ArrayList
            [void]$results.Add([pscustomobject]@{
                name = 'System'
                status = 'Succeeded'
                outputFiles = @('evidence/system/system.json')
                warnings = @()
                error = $null
            })
            [void]$results.Add([pscustomobject]@{
                name = 'EventLogs'
                status = 'Partial'
                outputFiles = @('evidence/events/channels.json')
                warnings = @(
                    "Event channel 'Security' is unavailable: access is denied.",
                    'Event export was bounded at the configured limit.'
                )
                error = $null
                issues = @(
                    [pscustomobject]@{
                        code = 'LIMIT_REACHED'
                        severity = 'Warning'
                        component = 'EventLogs'
                        message = 'Event export was bounded at the configured limit.'
                        source = 'Security'
                        details = [ordered]@{ MaximumEvents = 250 }
                    }
                )
            })
            $context = [pscustomobject]@{
                CapsuleId = 'IC-COVERAGE'
                Configuration = $configuration
                CollectorResults = $results
            }

            $coverage = New-ICCoverageData -Context $context

            $coverage.summary.selectedCollectors | Should -Be 2
            $coverage.summary.succeeded | Should -Be 1
            $coverage.summary.partial | Should -Be 1
            $coverage.summary.notSelected | Should -Be (@($script:ICCollectorDefinitions.Keys).Count - 2)
            @($coverage.issues).Count | Should -Be 2
            $coverage.issues.code | Should -Contain 'ACCESS_DENIED'
            $coverage.issues.code | Should -Contain 'LIMIT_REACHED'
            @($coverage.issues | Where-Object code -eq 'LIMIT_REACHED').Count | Should -Be 1
            ($coverage.issues | Where-Object code -eq 'LIMIT_REACHED').details.MaximumEvents | Should -Be 250
            $coverage.schemaVersion | Should -Be $script:ICSchemaVersion
        }
    }

    It 'reports privacy switches and resource limits explicitly' {
        InModuleScope IncidentCapsule {
            $configuration = Get-ICDefaultConfiguration -Profile Standard
            $privacy = Get-ICPrivacyScope -Configuration $configuration
            $limits = Get-ICResourceLimit -Configuration $configuration

            $privacy.PSObject.Properties.Name + @($privacy.Keys) | Should -Contain 'processCommandLines'
            $privacy.spreadsheetSafeCsv | Should -BeTrue
            $limits.Keys | Should -Contain 'MaximumCapsuleBytes'
            $limits.Keys | Should -Contain 'NativeCommandTimeoutSeconds'
            $limits.Keys | Should -Contain 'MaximumTimelineEntries'
            $limits.Keys | Should -Contain 'MaximumArchiveExpandedBytes'
        }
    }

    It 'keeps empty collector and issue collections schema-shaped under StrictMode' {
        InModuleScope IncidentCapsule {
            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $configuration.Collectors = @('System')
            $context = [pscustomobject]@{
                CapsuleId = 'IC-EMPTY-COVERAGE'
                Configuration = $configuration
                CollectorResults = @()
            }

            $coverage = New-ICCoverageData -Context $context

            $coverage.summary.selectedCollectors | Should -Be 1
            $coverage.summary.notRun | Should -Be 1
            $coverage.summary.issueCount | Should -Be 0
            @($coverage.collectors).Count | Should -Be (@($script:ICCollectorDefinitions.Keys).Count)
            @($coverage.issues).Count | Should -Be 0
        }
    }

    It 'keeps emitted privacy and resource fields within the coverage schema' {
        $schemaPath = Join-Path $repositoryRoot 'docs/schemas/coverage.schema.json'
        InModuleScope IncidentCapsule -Parameters @{ SchemaPath = $schemaPath } {
            param($SchemaPath)

            $schema = Get-Content -LiteralPath $SchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $configuration = Get-ICDefaultConfiguration -Profile Standard
            $context = [pscustomobject]@{
                CapsuleId       = 'IC-SCHEMA-COVERAGE'
                Configuration   = $configuration
                CollectorResults = @()
            }
            $coverage = New-ICCoverageData -Context $context
            $privacyProperties = @($schema.properties.privacyScope.properties.PSObject.Properties.Name)
            $resourceProperties = @($schema.properties.resourceLimits.properties.PSObject.Properties.Name)

            @($coverage.privacyScope.Keys | Where-Object { $_ -notin $privacyProperties }).Count | Should -Be 0
            @($coverage.resourceLimits.Keys | Where-Object { $_ -notin $resourceProperties }).Count | Should -Be 0
            @($schema.properties.privacyScope.required) | Should -Contain 'spreadsheetSafeCsv'
        }
    }
}

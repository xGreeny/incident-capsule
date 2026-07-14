$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule fail-closed finalization' {
    It 'treats an invalid directory integrity result as fatal' {
        $outputPath = Join-Path $TestDrive 'invalid-directory'
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $outputPath } {
            param($OutputPath)

            Mock Invoke-ICCollectors {
                $collectorResult = [pscustomobject]@{ status = 'Succeeded' }
                [void]$Context.CollectorResults.Add($collectorResult)
                @($collectorResult)
            }
            Mock New-ICTimelineIndex { [pscustomobject]@{} }
            Mock Write-ICCoverageData { $null }
            Mock New-ICHtmlReport { $null }
            Mock Test-ICDirectoryIntegrity {
                [pscustomobject]@{
                    IsValid        = $false
                    FilesMissing   = 1
                    FilesModified  = 0
                    FilesUnexpected = 0
                }
            }

            $caught = $null
            try {
                Invoke-IncidentCapsule `
                    -OutputPath $OutputPath `
                    -CaseId 'FINALIZATION-INVALID-DIRECTORY' `
                    -Profile Minimal `
                    -Collectors System `
                    -NoCompression
            }
            catch {
                $caught = $_
            }

            $caught | Should -Not -BeNullOrEmpty
            $caught.Exception.Message | Should -Match 'integrity verification failed'
            $result = $caught.Exception.Data['IncidentCapsuleResult']
            $result.Status | Should -Be 'Failed'
            $result.CollectionStatus | Should -Be 'Completed'
            $result.FinalizationStatus | Should -Be 'Failed'
            $result.IntegrityValid | Should -BeFalse
            $result.WorkingDirectory | Should -Exist
        }
    }

    It 'retains the working directory when archive verification fails' {
        $outputPath = Join-Path $TestDrive 'invalid-archive'
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $outputPath } {
            param($OutputPath)

            Mock Invoke-ICCollectors {
                $collectorResult = [pscustomobject]@{ status = 'Succeeded' }
                [void]$Context.CollectorResults.Add($collectorResult)
                @($collectorResult)
            }
            Mock New-ICTimelineIndex { [pscustomobject]@{} }
            Mock Write-ICCoverageData { $null }
            Mock New-ICHtmlReport { $null }
            Mock Test-IncidentCapsuleIntegrity {
                [pscustomobject][ordered]@{
                    PSTypeName        = 'IncidentCapsule.IntegrityResult'
                    Path              = $Path
                    SourceType        = 'Archive'
                    CapsuleId         = 'IC-FINALIZATION-INVALID-ARCHIVE'
                    SchemaVersion     = '1.1'
                    Algorithm         = 'SHA256'
                    IsValid           = $false
                    ArchiveHashValid  = $true
                    ChecksumListValid = $true
                    FilesExpected     = 1
                    FilesValid        = 0
                    FilesMissing      = 1
                    FilesModified     = 0
                    FilesUnexpected   = 0
                    FileResults       = @()
                    ArchivePolicy     = [pscustomobject][ordered]@{
                        EntryCount              = 1
                        ExpandedBytes           = 1024
                        UncompressedBytes       = 1024
                        CompressionRatio        = 1.0
                        MaximumEntries          = 20000
                        MaximumEntryBytes       = 1073741824L
                        MaximumExpandedBytes    = 21474836480L
                        MaximumCompressionRatio = 250.0
                    }
                    ArchiveEntryCount        = 1
                    ArchiveUncompressedBytes = 1024
                    ArchiveCompressionRatio  = 1.0
                }
            }
            Mock Write-ICVerificationReceipt {
                $receiptPath = "$ArchivePath.verification.json"
                [void](Write-ICJsonFile -Path $receiptPath -InputObject ([ordered]@{
                    schemaVersion     = '1.1'
                    archive           = Split-Path -Leaf $ArchivePath
                    capsuleId         = $Verification.CapsuleId
                    isValid           = [bool]$Verification.IsValid
                    archiveHashValid  = $Verification.ArchiveHashValid
                    checksumListValid = [bool]$Verification.ChecksumListValid
                    archivePolicy     = $Verification.ArchivePolicy
                }) -Depth 8)
                $receiptPath
            }

            $caught = $null
            try {
                Invoke-IncidentCapsule `
                    -OutputPath $OutputPath `
                    -CaseId 'FINALIZATION-INVALID-ARCHIVE' `
                    -Profile Minimal `
                    -Collectors System `
                    -RemoveWorkingDirectory
            }
            catch {
                $caught = $_
            }

            $caught | Should -Not -BeNullOrEmpty
            $result = $caught.Exception.Data['IncidentCapsuleResult']
            $result.Status | Should -Be 'Failed'
            $result.FinalizationStatus | Should -Be 'Failed'
            $result.IntegrityValid | Should -BeFalse
            $result.WorkingDirectory | Should -Exist
            $result.ArchivePath | Should -Exist
            $result.ArchiveVerificationPath | Should -Exist
            Should -Invoke Test-IncidentCapsuleIntegrity -Times 1 -Exactly -ParameterFilter {
                $RequireSidecar -and $MaximumArchiveEntries -eq 20000
            }
            Should -Invoke Write-ICVerificationReceipt -Times 1 -Exactly
        }
    }

    It 'removes working evidence only after verified archive handoff' {
        $outputPath = Join-Path $TestDrive 'verified-archive'
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $outputPath } {
            param($OutputPath)

            Mock Invoke-ICCollectors {
                $collectorResult = [pscustomobject]@{ status = 'Succeeded' }
                [void]$Context.CollectorResults.Add($collectorResult)
                @($collectorResult)
            }
            Mock New-ICTimelineIndex { [pscustomobject]@{} }
            Mock Write-ICCoverageData { $null }
            Mock New-ICHtmlReport { $null }
            Mock Test-IncidentCapsuleIntegrity {
                $capsuleRoot = $Path.Substring(0, $Path.Length - 4)
                if (-not (Test-Path -LiteralPath $capsuleRoot -PathType Container)) {
                    throw 'Working directory was removed before archive verification.'
                }
                [pscustomobject][ordered]@{
                    PSTypeName        = 'IncidentCapsule.IntegrityResult'
                    Path              = $Path
                    SourceType        = 'Archive'
                    CapsuleId         = 'IC-FINALIZATION-VERIFIED-ARCHIVE'
                    SchemaVersion     = '1.1'
                    Algorithm         = 'SHA256'
                    IsValid           = $true
                    ArchiveHashValid  = $true
                    ChecksumListValid = $true
                    FilesExpected     = 1
                    FilesValid        = 1
                    FilesMissing      = 0
                    FilesModified     = 0
                    FilesUnexpected   = 0
                    FileResults       = @()
                    ArchivePolicy     = [pscustomobject][ordered]@{
                        EntryCount              = 1
                        ExpandedBytes           = 1024
                        UncompressedBytes       = 1024
                        CompressionRatio        = 1.0
                        MaximumEntries          = 20000
                        MaximumEntryBytes       = 1073741824L
                        MaximumExpandedBytes    = 21474836480L
                        MaximumCompressionRatio = 250.0
                    }
                    ArchiveEntryCount        = 1
                    ArchiveUncompressedBytes = 1024
                    ArchiveCompressionRatio  = 1.0
                }
            }
            Mock Write-ICVerificationReceipt {
                $receiptPath = "$ArchivePath.verification.json"
                [void](Write-ICJsonFile -Path $receiptPath -InputObject ([ordered]@{
                    schemaVersion     = '1.1'
                    archive           = Split-Path -Leaf $ArchivePath
                    capsuleId         = $Verification.CapsuleId
                    isValid           = [bool]$Verification.IsValid
                    archiveHashValid  = $Verification.ArchiveHashValid
                    checksumListValid = [bool]$Verification.ChecksumListValid
                    archivePolicy     = $Verification.ArchivePolicy
                }) -Depth 8)
                $receiptPath
            }

            $result = Invoke-IncidentCapsule `
                -OutputPath $OutputPath `
                -CaseId 'FINALIZATION-VERIFIED-ARCHIVE' `
                -Profile Minimal `
                -Collectors System `
                -RemoveWorkingDirectory

            $result.Status | Should -Be 'Completed'
            $result.CollectionStatus | Should -Be 'Completed'
            $result.FinalizationStatus | Should -Be 'Verified'
            $result.IntegrityValid | Should -BeTrue
            $result.WorkingDirectory | Should -BeNullOrEmpty
            $result.ArchivePath | Should -Exist
            $result.ArchiveChecksumPath | Should -Exist
            $result.ArchiveVerificationPath | Should -Exist
            Should -Invoke Test-IncidentCapsuleIntegrity -Times 1 -Exactly
            Should -Invoke Write-ICVerificationReceipt -Times 1 -Exactly
        }
    }

    It 'embeds coverage and timeline handoff summaries in capsule metadata' {
        $outputPath = Join-Path $TestDrive 'metadata-handoff'
        InModuleScope IncidentCapsule -Parameters @{ OutputPath = $outputPath } {
            param($OutputPath)

            $configuration = Get-ICDefaultConfiguration -Profile Minimal
            $context = New-ICContext `
                -OutputPath $OutputPath `
                -CaseId 'METADATA-HANDOFF' `
                -Operator 'Pester' `
                -Profile Minimal `
                -Configuration $configuration
            $context.CompletedAtUtc = [datetime]::UtcNow
            $context.Status = 'Completed'
            $context.CollectionStatus = 'Completed'
            $context.FinalizationStatus = 'Sealing'

            $coveragePath = Join-Path $context.MetadataPath 'coverage.json'
            Write-ICUtf8File -Path $coveragePath -Content '{}' | Out-Null
            $context | Add-Member -NotePropertyName CoveragePath -NotePropertyValue $coveragePath
            $context | Add-Member -NotePropertyName Coverage -NotePropertyValue ([ordered]@{
                summary = [ordered]@{ succeeded = 4; partial = 1; issueCount = 2 }
            })

            $analysisPath = Join-Path $context.RootPath 'analysis'
            New-Item -ItemType Directory -Path $analysisPath -Force | Out-Null
            $timelineJsonPath = Join-Path $analysisPath 'timeline.json'
            $timelineCsvPath = Join-Path $analysisPath 'timeline.csv'
            Write-ICUtf8File -Path $timelineJsonPath -Content '{}' | Out-Null
            Write-ICUtf8File -Path $timelineCsvPath -Content '' | Out-Null
            $context | Add-Member -NotePropertyName Timeline -NotePropertyValue ([pscustomobject]@{
                JsonPath              = $timelineJsonPath
                CsvPath               = $timelineCsvPath
                SourceFiles           = 3
                SourceFilesRead       = 3
                SourceFilesFailed     = 0
                CandidateCount        = 12
                InvalidTimestampCount = 1
                EntryCount            = 10
                MaximumEntries        = 10
                Truncated             = $true
            })

            $metadata = New-ICCapsuleMetadata -Context $context
            $metadata.coverage.available | Should -BeTrue
            $metadata.coverage.path | Should -Be 'metadata/coverage.json'
            $metadata.coverage.summary.succeeded | Should -Be 4
            $metadata.timeline.available | Should -BeTrue
            $metadata.timeline.jsonPath | Should -Be 'analysis/timeline.json'
            $metadata.timeline.csvPath | Should -Be 'analysis/timeline.csv'
            $metadata.timeline.entryCount | Should -Be 10
            $metadata.timeline.truncated | Should -BeTrue
        }
    }
}

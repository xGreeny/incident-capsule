function Get-ICDefenderEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $statusData = $null
    $preferenceData = $null
    $detections = @()
    $threats = @()

    if (-not (Test-ICCommandAvailable -Name 'Get-MpComputerStatus')) {
        Add-ICCollectorWarning -List $warnings -Message 'Microsoft Defender PowerShell cmdlets are unavailable.'
    }
    else {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $statusData = [ordered]@{
                AMServiceEnabled = Get-ICPropertyValue -InputObject $status -Name 'AMServiceEnabled'
                AMServiceVersion = Get-ICPropertyValue -InputObject $status -Name 'AMServiceVersion'
                AntispywareEnabled = Get-ICPropertyValue -InputObject $status -Name 'AntispywareEnabled'
                AntispywareSignatureAge = Get-ICPropertyValue -InputObject $status -Name 'AntispywareSignatureAge'
                AntispywareSignatureLastUpdatedUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $status -Name 'AntispywareSignatureLastUpdated')
                AntispywareSignatureVersion = Get-ICPropertyValue -InputObject $status -Name 'AntispywareSignatureVersion'
                AntivirusEnabled = Get-ICPropertyValue -InputObject $status -Name 'AntivirusEnabled'
                AntivirusSignatureAge = Get-ICPropertyValue -InputObject $status -Name 'AntivirusSignatureAge'
                AntivirusSignatureLastUpdatedUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $status -Name 'AntivirusSignatureLastUpdated')
                AntivirusSignatureVersion = Get-ICPropertyValue -InputObject $status -Name 'AntivirusSignatureVersion'
                BehaviorMonitorEnabled = Get-ICPropertyValue -InputObject $status -Name 'BehaviorMonitorEnabled'
                ComputerID = Get-ICPropertyValue -InputObject $status -Name 'ComputerID'
                ComputerState = Get-ICPropertyValue -InputObject $status -Name 'ComputerState'
                DefenderSignaturesOutOfDate = Get-ICPropertyValue -InputObject $status -Name 'DefenderSignaturesOutOfDate'
                DeviceControlDefaultEnforcement = Get-ICPropertyValue -InputObject $status -Name 'DeviceControlDefaultEnforcement'
                FullScanAge = Get-ICPropertyValue -InputObject $status -Name 'FullScanAge'
                FullScanEndTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $status -Name 'FullScanEndTime')
                FullScanOverdue = Get-ICPropertyValue -InputObject $status -Name 'FullScanOverdue'
                IoavProtectionEnabled = Get-ICPropertyValue -InputObject $status -Name 'IoavProtectionEnabled'
                IsTamperProtected = Get-ICPropertyValue -InputObject $status -Name 'IsTamperProtected'
                NISEnabled = Get-ICPropertyValue -InputObject $status -Name 'NISEnabled'
                NISEngineVersion = Get-ICPropertyValue -InputObject $status -Name 'NISEngineVersion'
                NISSignatureAge = Get-ICPropertyValue -InputObject $status -Name 'NISSignatureAge'
                NISSignatureLastUpdatedUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $status -Name 'NISSignatureLastUpdated')
                NISSignatureVersion = Get-ICPropertyValue -InputObject $status -Name 'NISSignatureVersion'
                OnAccessProtectionEnabled = Get-ICPropertyValue -InputObject $status -Name 'OnAccessProtectionEnabled'
                ProductStatus = Get-ICPropertyValue -InputObject $status -Name 'ProductStatus'
                QuickScanAge = Get-ICPropertyValue -InputObject $status -Name 'QuickScanAge'
                QuickScanEndTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $status -Name 'QuickScanEndTime')
                QuickScanOverdue = Get-ICPropertyValue -InputObject $status -Name 'QuickScanOverdue'
                RealTimeProtectionEnabled = Get-ICPropertyValue -InputObject $status -Name 'RealTimeProtectionEnabled'
                RealTimeScanDirection = Get-ICPropertyValue -InputObject $status -Name 'RealTimeScanDirection'
                RebootRequired = Get-ICPropertyValue -InputObject $status -Name 'RebootRequired'
                SmartAppControlState = Get-ICPropertyValue -InputObject $status -Name 'SmartAppControlState'
                TamperProtectionSource = Get-ICPropertyValue -InputObject $status -Name 'TamperProtectionSource'
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Defender status: $($_.Exception.Message)" }

        if ($Context.Configuration.CollectDefenderPreferences -and (Test-ICCommandAvailable -Name 'Get-MpPreference')) {
            try {
                $preference = Get-MpPreference -ErrorAction Stop
                $preferenceData = [ordered]@{
                    AttackSurfaceReductionOnlyExclusions = @(Get-ICPropertyValue -InputObject $preference -Name 'AttackSurfaceReductionOnlyExclusions')
                    AttackSurfaceReductionRulesIds = @(Get-ICPropertyValue -InputObject $preference -Name 'AttackSurfaceReductionRules_Ids')
                    AttackSurfaceReductionRulesActions = @(Get-ICPropertyValue -InputObject $preference -Name 'AttackSurfaceReductionRules_Actions')
                    AttackSurfaceReductionRulesRuleSpecificExclusions = @(Get-ICPropertyValue -InputObject $preference -Name 'AttackSurfaceReductionRules_RuleSpecificExclusions')
                    CloudBlockLevel = Get-ICPropertyValue -InputObject $preference -Name 'CloudBlockLevel'
                    CloudExtendedTimeout = Get-ICPropertyValue -InputObject $preference -Name 'CloudExtendedTimeout'
                    ControlledFolderAccessAllowedApplications = @(Get-ICPropertyValue -InputObject $preference -Name 'ControlledFolderAccessAllowedApplications')
                    ControlledFolderAccessProtectedFolders = @(Get-ICPropertyValue -InputObject $preference -Name 'ControlledFolderAccessProtectedFolders')
                    DisableArchiveScanning = Get-ICPropertyValue -InputObject $preference -Name 'DisableArchiveScanning'
                    DisableBehaviorMonitoring = Get-ICPropertyValue -InputObject $preference -Name 'DisableBehaviorMonitoring'
                    DisableBlockAtFirstSeen = Get-ICPropertyValue -InputObject $preference -Name 'DisableBlockAtFirstSeen'
                    DisableIOAVProtection = Get-ICPropertyValue -InputObject $preference -Name 'DisableIOAVProtection'
                    DisableIntrusionPreventionSystem = Get-ICPropertyValue -InputObject $preference -Name 'DisableIntrusionPreventionSystem'
                    DisableRealtimeMonitoring = Get-ICPropertyValue -InputObject $preference -Name 'DisableRealtimeMonitoring'
                    DisableScriptScanning = Get-ICPropertyValue -InputObject $preference -Name 'DisableScriptScanning'
                    EnableControlledFolderAccess = Get-ICPropertyValue -InputObject $preference -Name 'EnableControlledFolderAccess'
                    EnableNetworkProtection = Get-ICPropertyValue -InputObject $preference -Name 'EnableNetworkProtection'
                    ExclusionExtension = @(Get-ICPropertyValue -InputObject $preference -Name 'ExclusionExtension')
                    ExclusionIpAddress = @(Get-ICPropertyValue -InputObject $preference -Name 'ExclusionIpAddress')
                    ExclusionPath = @(Get-ICPropertyValue -InputObject $preference -Name 'ExclusionPath')
                    ExclusionProcess = @(Get-ICPropertyValue -InputObject $preference -Name 'ExclusionProcess')
                    MAPSReporting = Get-ICPropertyValue -InputObject $preference -Name 'MAPSReporting'
                    PUAProtection = Get-ICPropertyValue -InputObject $preference -Name 'PUAProtection'
                    QuarantinePurgeItemsAfterDelay = Get-ICPropertyValue -InputObject $preference -Name 'QuarantinePurgeItemsAfterDelay'
                    ScanAvgCPULoadFactor = Get-ICPropertyValue -InputObject $preference -Name 'ScanAvgCPULoadFactor'
                    ScanParameters = Get-ICPropertyValue -InputObject $preference -Name 'ScanParameters'
                    SignatureUpdateInterval = Get-ICPropertyValue -InputObject $preference -Name 'SignatureUpdateInterval'
                    SubmitSamplesConsent = Get-ICPropertyValue -InputObject $preference -Name 'SubmitSamplesConsent'
                }
            }
            catch { Add-ICCollectorWarning -List $warnings -Message "Defender preferences: $($_.Exception.Message)" }
        }

        if (Test-ICCommandAvailable -Name 'Get-MpThreatDetection') {
            try {
                $cutoff = (Get-Date).AddDays(-30)
                $detections = @(Get-MpThreatDetection -ErrorAction Stop |
                    Where-Object { $null -eq $_.InitialDetectionTime -or $_.InitialDetectionTime -ge $cutoff } |
                    ForEach-Object {
                        [pscustomobject][ordered]@{
                            ThreatID = $_.ThreatID
                            ThreatStatusID = $_.ThreatStatusID
                            InitialDetectionTimeUtc = ConvertTo-ICIso8601 -Value $_.InitialDetectionTime
                            LastThreatStatusChangeTimeUtc = ConvertTo-ICIso8601 -Value $_.LastThreatStatusChangeTime
                            RemediationTimeUtc = ConvertTo-ICIso8601 -Value $_.RemediationTime
                            ActionSuccess = $_.ActionSuccess
                            CurrentThreatExecutionStatusID = $_.CurrentThreatExecutionStatusID
                            DetectionID = $_.DetectionID
                            DomainUser = $_.DomainUser
                            ProcessName = $_.ProcessName
                            Resources = @($_.Resources)
                        }
                    })
            }
            catch { Add-ICCollectorWarning -List $warnings -Message "Defender threat detections: $($_.Exception.Message)" }
        }

        if (Test-ICCommandAvailable -Name 'Get-MpThreat') {
            try {
                $threats = @(Get-MpThreat -ErrorAction Stop | ForEach-Object {
                    [pscustomobject][ordered]@{
                        ThreatID = $_.ThreatID
                        ThreatName = $_.ThreatName
                        SeverityID = $_.SeverityID
                        CategoryID = $_.CategoryID
                        DidThreatExecute = $_.DidThreatExecute
                        IsActive = $_.IsActive
                        Resources = @($_.Resources)
                    }
                })
            }
            catch { Add-ICCollectorWarning -List $warnings -Message "Defender threat summary: $($_.Exception.Message)" }
        }
    }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Defender -RelativePath 'evidence/defender/status.json' -Data $statusData)
    if ($Context.Configuration.CollectDefenderPreferences) {
        Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Defender -RelativePath 'evidence/defender/preferences.json' -Data $preferenceData)
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Defender -RelativePath 'evidence/defender/threat-detections.json' -Data $detections -Csv)
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Defender -RelativePath 'evidence/defender/threats.json' -Data $threats -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        DefenderAvailable = $null -ne $statusData
        RealTimeProtectionEnabled = if ($null -ne $statusData) { $statusData.RealTimeProtectionEnabled } else { $null }
        AntivirusSignatureAge = if ($null -ne $statusData) { $statusData.AntivirusSignatureAge } else { $null }
        TamperProtected = if ($null -ne $statusData) { $statusData.IsTamperProtected } else { $null }
        ThreatDetectionsLast30Days = $detections.Count
        ActiveThreats = @($threats | Where-Object IsActive -eq $true).Count
    })
}

@{
    # These 23 warnings predate v1.1.0. Fingerprints deliberately omit line
    # numbers so harmless edits do not invalidate the review. Duplicate entries
    # preserve multiplicity. New warnings still fail the Analyze task.
    Warnings = @(
        "PSUseSingularNouns|build.ps1|The cmdlet 'Invoke-RepositoryTests' uses a plural noun. A singular noun should be used instead."
        "PSAvoidAssignmentToAutomaticVariable|tools/Invoke-IncidentCapsule.ps1|The Variable 'Profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSAvoidAssignmentToAutomaticVariable|src/IncidentCapsule/Public/Invoke-IncidentCapsule.ps1|The Variable 'Profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSAvoidAssignmentToAutomaticVariable|src/IncidentCapsule/Private/Configuration.ps1|The Variable 'Profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSAvoidAssignmentToAutomaticVariable|src/IncidentCapsule/Private/Configuration.ps1|The Variable 'Profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSAvoidAssignmentToAutomaticVariable|src/IncidentCapsule/Private/Configuration.ps1|The Variable 'Profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSUseSingularNouns|src/IncidentCapsule/Private/Configuration.ps1|The cmdlet 'Get-ICDefaultEventLogs' uses a plural noun. A singular noun should be used instead."
        "PSAvoidAssignmentToAutomaticVariable|src/IncidentCapsule/Private/Context.ps1|The Variable 'Profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSAvoidUsingEmptyCatchBlock|src/IncidentCapsule/Private/CollectorEngine.ps1|Empty catch block is used. Please use Write-Error or throw statements in catch blocks."
        "PSAvoidUsingEmptyCatchBlock|src/IncidentCapsule/Private/CollectorEngine.ps1|Empty catch block is used. Please use Write-Error or throw statements in catch blocks."
        "PSUseSingularNouns|src/IncidentCapsule/Private/CollectorEngine.ps1|The cmdlet 'Invoke-ICCollectors' uses a plural noun. A singular noun should be used instead."
        "PSUseSingularNouns|src/IncidentCapsule/Private/CollectorEngine.ps1|The cmdlet 'New-ICCapsuleMetadata' uses a plural noun. A singular noun should be used instead."
        "PSUseSingularNouns|src/IncidentCapsule/Private/Collectors.Common.ps1|The cmdlet 'Add-ICOutputFiles' uses a plural noun. A singular noun should be used instead."
        "PSAvoidUsingEmptyCatchBlock|src/IncidentCapsule/Private/Collectors.Network.ps1|Empty catch block is used. Please use Write-Error or throw statements in catch blocks."
        "PSAvoidUsingEmptyCatchBlock|src/IncidentCapsule/Private/Collectors.Persistence.ps1|Empty catch block is used. Please use Write-Error or throw statements in catch blocks."
        "PSAvoidAssignmentToAutomaticVariable|src/IncidentCapsule/Private/Collectors.Persistence.ps1|The Variable 'profile' is an automatic variable that is built into PowerShell, assigning to it might have undesired side effects. If assignment is not by design, please use a different name."
        "PSAvoidUsingEmptyCatchBlock|src/IncidentCapsule/Private/Collectors.PowerShell.ps1|Empty catch block is used. Please use Write-Error or throw statements in catch blocks."
        "PSAvoidUsingEmptyCatchBlock|src/IncidentCapsule/Private/Collectors.System.ps1|Empty catch block is used. Please use Write-Error or throw statements in catch blocks."
        "PSUseSingularNouns|src/IncidentCapsule/Private/IO.ps1|The cmdlet 'Get-ICRegistryValues' uses a plural noun. A singular noun should be used instead."
        "PSUseSingularNouns|src/IncidentCapsule/Private/IO.ps1|The cmdlet 'Get-ICFileMetadata' uses a plural noun. A singular noun should be used instead."
        "PSUseSingularNouns|src/IncidentCapsule/Private/Manifest.ps1|The cmdlet 'Get-ICManifestFiles' uses a plural noun. A singular noun should be used instead."
        "PSUseBOMForUnicodeEncodedFile|src/IncidentCapsule/Private/Report.ps1|Missing BOM encoding for non-ASCII encoded file 'Report.ps1'"
        "PSUseSingularNouns|src/IncidentCapsule/Private/Report.ps1|The cmdlet 'ConvertTo-ICMetricRows' uses a plural noun. A singular noun should be used instead."
    )
}

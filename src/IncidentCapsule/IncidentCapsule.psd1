@{
    RootModule        = 'IncidentCapsule.psm1'
    ModuleVersion     = '1.3.1'
    GUID              = 'f4f29bb2-65a6-4e50-8548-4547f4d4f9e6'
    Author            = 'xGreeny'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 xGreeny and Incident Capsule contributors. MIT License.'
    Description       = 'Read-only Windows first-response evidence collection with offline reporting and hardened SHA-256 integrity verification.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'Compare-IncidentCapsule',
        'Export-IncidentCapsuleData',
        'Get-IncidentCapsuleProfile',
        'Invoke-IncidentCapsule',
        'Test-IncidentCapsuleReadiness',
        'Test-IncidentCapsuleIntegrity'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @(
                'IncidentResponse', 'DFIR', 'Windows', 'PowerShell', 'Triage',
                'SecurityOperations', 'Evidence', 'Forensics', 'BlueTeam'
            )
            LicenseUri   = 'https://github.com/xGreeny/incident-capsule/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/xGreeny/incident-capsule'
            ReleaseNotes = 'Fixes the AppCompatCache (Shimcache) export, which was skipped on every host because the REG_BINARY value was enumerated to object[] before the byte-array type check.'
        }
    }
}

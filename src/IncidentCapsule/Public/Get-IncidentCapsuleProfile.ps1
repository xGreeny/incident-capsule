function Get-IncidentCapsuleProfile {
    <#
    .SYNOPSIS
    Returns the built-in Incident Capsule collection profiles.

    .DESCRIPTION
    Displays the effective defaults for the Minimal, Standard, or Extended profile,
    including collector selection, event lookback, native EVTX export, and bounded
    high-detail options.

    .PARAMETER Name
    Optional profile name. Without it, all profiles are returned.

    .EXAMPLE
    Get-IncidentCapsuleProfile

    .EXAMPLE
    Get-IncidentCapsuleProfile -Name Extended | Format-List *
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Minimal', 'Standard', 'Extended')]
        [string]$Name
    )

    $names = if ($PSBoundParameters.ContainsKey('Name')) { @($Name) } else { @('Minimal', 'Standard', 'Extended') }
    foreach ($profileName in $names) {
        $configuration = Get-ICDefaultConfiguration -Profile $profileName
        $description = switch ($profileName) {
            'Minimal'  { 'Fast triage with a reduced collector set and decoded event summaries.' }
            'Standard' { 'Default first-response package with all collectors and bounded EVTX export.' }
            'Extended' { 'Deeper collection with longer event coverage and bounded image/driver hashing.' }
        }

        $profileRecord = [ordered]@{
            PSTypeName  = 'IncidentCapsule.Profile'
            Name        = $profileName
            Description = $description
        }
        foreach ($configurationKey in $script:ICConfigurationKeys) {
            $profileRecord[$configurationKey] = Copy-ICValue -Value $configuration[$configurationKey]
        }
        $profileRecord.Configuration = Copy-ICValue -Value $configuration

        [pscustomobject]$profileRecord
    }
}

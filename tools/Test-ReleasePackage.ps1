[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageRoot,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [version]$ExpectedVersion
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$resolvedPackageRoot = (
    Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop
).ProviderPath
$modulePath = Join-Path $resolvedPackageRoot 'IncidentCapsule/IncidentCapsule.psd1'
$launcherPath = Join-Path $resolvedPackageRoot 'Invoke-IncidentCapsule.ps1'

if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Packaged module manifest is missing: $modulePath"
}

if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
    throw "Packaged launcher is missing: $launcherPath"
}

$manifest = Test-ModuleManifest -Path $modulePath -ErrorAction Stop
if ($manifest.Version -ne $ExpectedVersion) {
    throw (
        "Packaged module version '{0}' does not match expected version '{1}'." -f
        $manifest.Version,
        $ExpectedVersion
    )
}

Import-Module $modulePath -Force -ErrorAction Stop
$loadedModule = Get-Module -Name IncidentCapsule | Select-Object -First 1

if ($null -eq $loadedModule) {
    throw 'The packaged IncidentCapsule module was not loaded.'
}

$expectedModuleBase = Split-Path $modulePath -Parent
if (-not $loadedModule.ModuleBase.Equals(
        $expectedModuleBase,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
    throw (
        "Module was loaded from '{0}' instead of the extracted package '{1}'." -f
        $loadedModule.ModuleBase,
        $expectedModuleBase
    )
}

foreach ($commandName in @(
        'Get-IncidentCapsuleProfile',
        'Invoke-IncidentCapsule',
        'Test-IncidentCapsuleReadiness',
        'Test-IncidentCapsuleIntegrity'
    )) {
    if ($null -eq (Get-Command -Name $commandName -Module IncidentCapsule -ErrorAction SilentlyContinue)) {
        throw "Packaged module does not export '$commandName'."
    }
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$editionName = [string]$PSVersionTable.PSEdition
$caseId = "PACKAGE-SMOKE-$($editionName.ToUpperInvariant())"
$launcherOutput = @(
    & $launcherPath `
        -OutputPath $OutputPath `
        -CaseId $caseId `
        -Profile Minimal `
        -Collectors System `
        -NoCompression
)

$result = @(
    $launcherOutput |
        Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['IntegrityValid']
        }
) | Select-Object -Last 1

if ($null -eq $result) {
    throw 'The packaged launcher did not return a capsule result.'
}

if ([string]$result.Status -eq 'Failed') {
    throw 'The packaged launcher returned a failed capsule result.'
}

if (-not [bool]$result.IntegrityValid) {
    throw 'The packaged launcher did not produce a valid capsule manifest.'
}

if (-not (Test-Path -LiteralPath $result.WorkingDirectory -PathType Container)) {
    throw "The packaged launcher did not create its working directory: $($result.WorkingDirectory)"
}

$verification = Test-IncidentCapsuleIntegrity -Path $result.WorkingDirectory
if (-not $verification.IsValid) {
    throw 'Integrity verification failed for the package smoke-test capsule.'
}

[pscustomobject]@{
    Edition         = $editionName
    PowerShell      = $PSVersionTable.PSVersion.ToString()
    ModuleVersion   = $manifest.Version.ToString()
    Status          = [string]$result.Status
    IntegrityValid  = [bool]$verification.IsValid
}

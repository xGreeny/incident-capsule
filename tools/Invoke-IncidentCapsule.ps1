[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,

    [string]$CaseId = ("IR-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')),

    [string]$Operator,

    [ValidateSet('Minimal', 'Standard', 'Extended')]
    [string]$Profile = 'Standard',

    [string]$ConfigurationPath,

    [ValidateSet(
        'System', 'Storage', 'Processes', 'Services', 'Network', 'Sessions',
        'LocalAccounts', 'ScheduledTasks', 'Persistence', 'Defender', 'PowerShell',
        'SecurityConfiguration', 'Hotfixes', 'Drivers', 'EventLogs'
    )]
    [string[]]$Collectors,

    [ValidateSet(
        'System', 'Storage', 'Processes', 'Services', 'Network', 'Sessions',
        'LocalAccounts', 'ScheduledTasks', 'Persistence', 'Defender', 'PowerShell',
        'SecurityConfiguration', 'Hotfixes', 'Drivers', 'EventLogs'
    )]
    [string[]]$ExcludeCollector,

    [switch]$NoCompression,

    [switch]$RemoveWorkingDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$moduleCandidates = @(
    (Join-Path $PSScriptRoot 'IncidentCapsule/IncidentCapsule.psd1')
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/IncidentCapsule/IncidentCapsule.psd1')
)

$modulePath = @(
    $moduleCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
) | Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($modulePath)) {
    throw (
        "IncidentCapsule module manifest was not found. Searched: {0}" -f
        ($moduleCandidates -join ', ')
    )
}

Import-Module $modulePath -Force -ErrorAction Stop

$parameters = @{
    OutputPath             = $OutputPath
    CaseId                = $CaseId
    Profile               = $Profile
    NoCompression         = $NoCompression
    RemoveWorkingDirectory = $RemoveWorkingDirectory
}

if ($PSBoundParameters.ContainsKey('Operator')) {
    $parameters.Operator = $Operator
}
if ($PSBoundParameters.ContainsKey('ConfigurationPath')) {
    $parameters.ConfigurationPath = $ConfigurationPath
}
if ($PSBoundParameters.ContainsKey('Collectors')) {
    $parameters.Collectors = $Collectors
}
if ($PSBoundParameters.ContainsKey('ExcludeCollector')) {
    $parameters.ExcludeCollector = $ExcludeCollector
}

Invoke-IncidentCapsule @parameters

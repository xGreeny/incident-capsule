Set-StrictMode -Version 2.0

$privatePath = Join-Path $PSScriptRoot 'Private'
$publicPath = Join-Path $PSScriptRoot 'Public'

Get-ChildItem -LiteralPath $privatePath -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

Get-ChildItem -LiteralPath $publicPath -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

Export-ModuleMember -Function @(
    'Export-IncidentCapsuleData',
    'Get-IncidentCapsuleProfile',
    'Invoke-IncidentCapsule',
    'Test-IncidentCapsuleReadiness',
    'Test-IncidentCapsuleIntegrity'
)

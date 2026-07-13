[CmdletBinding()]
param(
    [ValidateSet('Clean', 'Analyze', 'Test', 'Package', 'All')]
    [string]$Task = 'All',

    [string]$OutputPath = (Join-Path $PSScriptRoot 'out')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$moduleManifest = Join-Path $PSScriptRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
$testPath = Join-Path $PSScriptRoot 'tests'
$analyzerSettings = Join-Path $PSScriptRoot '.config/PSScriptAnalyzerSettings.psd1'

function Remove-BuildOutput {
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Recurse -Force
    }

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Invoke-StaticAnalysis {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        throw 'PSScriptAnalyzer is not installed. Install-Module PSScriptAnalyzer -Scope CurrentUser'
    }

    $paths = @(
        Join-Path $PSScriptRoot 'src'
        Join-Path $PSScriptRoot 'tools'
        Join-Path $PSScriptRoot 'tests'
        Join-Path $PSScriptRoot 'build.ps1'
    )

    $issues = @()
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            $issues += Invoke-ScriptAnalyzer -Path $path -Recurse -Settings $analyzerSettings
        }
    }

    if ($issues.Count -gt 0) {
        $issues | Sort-Object ScriptName, Line | Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize
    }

    $errors = @($issues | Where-Object Severity -eq 'Error')
    if ($errors.Count -gt 0) {
        throw "PSScriptAnalyzer reported $($errors.Count) error(s)."
    }
}

function Invoke-RepositoryTests {
    if (-not (Get-Module -ListAvailable -Name Pester | Where-Object Version -ge ([version]'5.5.0'))) {
        throw 'Pester 5.5.0 or newer is required. Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser'
    }

    $resultFile = Join-Path $OutputPath ("TestResults-{0}.xml" -f $PSVersionTable.PSEdition)
    $configuration = New-PesterConfiguration
    $configuration.Run.Path = $testPath
    $configuration.Run.PassThru = $true
    $configuration.Output.Verbosity = 'Detailed'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = $resultFile
    $configuration.TestResult.OutputFormat = 'NUnitXml'

    $result = Invoke-Pester -Configuration $configuration
    if ($result.FailedCount -gt 0) {
        throw "Pester reported $($result.FailedCount) failed test(s)."
    }
}

function New-ReleasePackage {
    $manifest = Test-ModuleManifest -Path $moduleManifest
    $version = $manifest.Version.ToString()
    $packageRootName = "incident-capsule-$version"
    $stagingRoot = Join-Path $OutputPath $packageRootName

    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'src/IncidentCapsule') -Destination (Join-Path $stagingRoot 'IncidentCapsule') -Recurse
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'tools/Invoke-IncidentCapsule.ps1') -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'CHANGELOG.md') -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE') -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SECURITY.md') -Destination $stagingRoot
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'docs') -Destination (Join-Path $stagingRoot 'docs') -Recurse
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'examples') -Destination (Join-Path $stagingRoot 'examples') -Recurse

    $archivePath = Join-Path $OutputPath "$packageRootName.zip"
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    Compress-Archive -LiteralPath $stagingRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
    $sidecarPath = "$archivePath.sha256"
    "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path -Leaf $archivePath) |
        Set-Content -LiteralPath $sidecarPath -Encoding ASCII

    [pscustomobject]@{
        Version      = $version
        ArchivePath  = $archivePath
        ChecksumPath = $sidecarPath
        SHA256       = $hash.Hash
    }
}

if ($Task -in @('Clean', 'All')) {
    Remove-BuildOutput
}
elseif (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

if ($Task -in @('Analyze', 'All')) {
    Invoke-StaticAnalysis
}

if ($Task -in @('Test', 'All')) {
    Invoke-RepositoryTests
}

if ($Task -in @('Package', 'All')) {
    New-ReleasePackage
}

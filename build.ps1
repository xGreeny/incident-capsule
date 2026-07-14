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
$requiredPesterVersion = [version]'5.9.0'
$requiredPSScriptAnalyzerVersion = [version]'1.25.0'

function Import-RequiredBuildModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [version]$RequiredVersion
    )

    $availableModule = Get-Module -ListAvailable -Name $Name |
        Where-Object { $_.Version -eq $RequiredVersion } |
        Select-Object -First 1

    if ($null -eq $availableModule) {
        throw ("{0} {1} is required. Run: Install-Module {0} -RequiredVersion {1} -Scope CurrentUser" -f $Name, $RequiredVersion)
    }

    Remove-Module -Name $Name -Force -ErrorAction SilentlyContinue
    Import-Module -Name $Name -RequiredVersion $RequiredVersion -Force -ErrorAction Stop

    $loadedModule = Get-Module -Name $Name | Select-Object -First 1
    if ($null -eq $loadedModule -or $loadedModule.Version -ne $RequiredVersion) {
        throw ("Failed to load {0} {1}. Loaded version: {2}" -f $Name, $RequiredVersion, $loadedModule.Version)
    }
}

function Remove-BuildOutput {
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Invoke-StaticAnalysis {
    Import-RequiredBuildModule -Name 'PSScriptAnalyzer' -RequiredVersion $requiredPSScriptAnalyzerVersion

    $paths = @(
        (Join-Path $PSScriptRoot 'src'),
        (Join-Path $PSScriptRoot 'tools'),
        (Join-Path $PSScriptRoot 'tests'),
        (Join-Path $PSScriptRoot 'build.ps1')
    )

    $issues = @()
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        $parameters = @{
            Path        = $item.FullName
            Settings    = $analyzerSettings
            ErrorAction = 'Stop'
        }
        if ($item.PSIsContainer) {
            $parameters.Recurse = $true
        }
        $issues += Invoke-ScriptAnalyzer @parameters
    }

    if ($issues.Count -gt 0) {
        $issues | Sort-Object ScriptName, Line | Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize
    }

    $blockingIssues = @($issues | Where-Object { @('Error', 'ParseError') -contains [string]$_.Severity })
    if ($blockingIssues.Count -gt 0) {
        throw "PSScriptAnalyzer reported $($blockingIssues.Count) blocking issue(s)."
    }
}

function Invoke-RepositoryTests {
    Import-RequiredBuildModule -Name 'Pester' -RequiredVersion $requiredPesterVersion

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
    if ($result.Result -ne 'Passed') {
        throw "Pester completed with result '$($result.Result)'."
    }
}

function New-ReleasePackage {
    $manifest = Test-ModuleManifest -Path $moduleManifest -ErrorAction Stop
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

    $verificationRoot = Join-Path $OutputPath ("verify-{0}" -f [guid]::NewGuid().ToString('N'))
    try {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $verificationRoot -Force
        $packagedManifest = Join-Path $verificationRoot "$packageRootName/IncidentCapsule/IncidentCapsule.psd1"
        $packagedModule = Test-ModuleManifest -Path $packagedManifest -ErrorAction Stop
        if ($packagedModule.Version -ne $manifest.Version) {
            throw "Packaged module version '$($packagedModule.Version)' does not match '$($manifest.Version)'."
        }
        Import-Module $packagedManifest -Force -ErrorAction Stop
    }
    finally {
        Remove-Module IncidentCapsule -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $verificationRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
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

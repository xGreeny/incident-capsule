[CmdletBinding()]
param(
    [ValidateSet('Clean', 'Analyze', 'Test', 'Package', 'All')]
    [string]$Task = 'All',

    [string]$OutputPath,

    [string]$ReleaseTag
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot 'out'
}

$moduleManifest = Join-Path $PSScriptRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
$runtimeConstants = Join-Path $PSScriptRoot 'src/IncidentCapsule/Private/00-Constants.ps1'
$changelogPath = Join-Path $PSScriptRoot 'CHANGELOG.md'
$testPath = Join-Path $PSScriptRoot 'tests'
$analyzerSettings = Join-Path $PSScriptRoot '.config/PSScriptAnalyzerSettings.psd1'
$analyzerBaseline = Join-Path $PSScriptRoot '.config/PSScriptAnalyzerBaseline.psd1'
$packageSmokeScript = Join-Path $PSScriptRoot 'tools/Test-ReleasePackage.ps1'

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
    $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $resolvedRepositoryPath = [System.IO.Path]::GetFullPath($PSScriptRoot)
    $resolvedVolumeRoot = [System.IO.Path]::GetPathRoot($resolvedOutputPath)

    if ($resolvedOutputPath.TrimEnd('\', '/') -eq $resolvedVolumeRoot.TrimEnd('\', '/') -or
        $resolvedOutputPath.TrimEnd('\', '/') -eq $resolvedRepositoryPath.TrimEnd('\', '/')) {
        throw "Refusing to recursively clean unsafe build output: $resolvedOutputPath"
    }

    if (Test-Path -LiteralPath $resolvedOutputPath) {
        Remove-Item -LiteralPath $resolvedOutputPath -Recurse -Force
    }

    New-Item -ItemType Directory -Path $resolvedOutputPath -Force | Out-Null
}

function Get-AnalyzerFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Issue
    )

    $repositoryPath = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $scriptPath = [System.IO.Path]::GetFullPath([string]$Issue.ScriptPath)

    if (-not $scriptPath.StartsWith(
            $repositoryPath + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Analyzer returned a path outside the repository: $scriptPath"
    }

    $relativePath = $scriptPath.Substring($repositoryPath.Length + 1).Replace('\', '/')
    '{0}|{1}|{2}' -f $Issue.RuleName, $relativePath, $Issue.Message
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

    if (-not (Test-Path -LiteralPath $analyzerBaseline -PathType Leaf)) {
        throw "PSScriptAnalyzer warning baseline is missing: $analyzerBaseline"
    }

    $baselineData = Import-PowerShellDataFile -LiteralPath $analyzerBaseline
    $remainingBaseline = New-Object 'System.Collections.Generic.List[string]'

    foreach ($fingerprint in @($baselineData.Warnings)) {
        $remainingBaseline.Add([string]$fingerprint)
    }

    $newWarnings = @()
    $warnings = @(
        $issues |
            Where-Object { [string]$_.Severity -eq 'Warning' }
    )

    foreach ($warning in $warnings) {
        $fingerprint = Get-AnalyzerFingerprint -Issue $warning
        $baselineIndex = $remainingBaseline.IndexOf($fingerprint)

        if ($baselineIndex -ge 0) {
            $remainingBaseline.RemoveAt($baselineIndex)
        }
        else {
            $newWarnings += $warning
        }
    }

    if ($newWarnings.Count -gt 0) {
        $newWarnings |
            Sort-Object ScriptName, Line |
            Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize

        throw (
            "PSScriptAnalyzer reported {0} warning(s) outside the reviewed baseline."
        ) -f $newWarnings.Count
    }

    if ($remainingBaseline.Count -gt 0) {
        throw (
            "PSScriptAnalyzer baseline contains {0} resolved warning(s). " +
            "Remove the stale entries in .config/PSScriptAnalyzerBaseline.psd1."
        ) -f $remainingBaseline.Count
    }

    Write-Verbose (
        "PSScriptAnalyzer baseline accepted {0} reviewed warning(s); no new warnings." -f
        $warnings.Count
    )
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

function Test-ProjectVersion {
    [CmdletBinding()]
    param(
        [string]$ExpectedTag
    )

    $manifest = Test-ModuleManifest -Path $moduleManifest -ErrorAction Stop
    $manifestVersion = [version]$manifest.Version
    $constantsContent = Get-Content -LiteralPath $runtimeConstants -Raw -ErrorAction Stop
    $literalRuntimeMatch = [regex]::Match(
        $constantsContent,
        '(?m)^\s*\$script:ICVersion\s*=\s*[''"](?<Version>[^''"]+)[''"]\s*$'
    )

    if ($literalRuntimeMatch.Success) {
        $runtimeVersion = [version]$literalRuntimeMatch.Groups['Version'].Value
    }
    elseif ([regex]::IsMatch(
            $constantsContent,
            '(?m)^\s*\$script:ICVersion\s*=\s*\[string\]\s*\$moduleManifestData\.ModuleVersion\s*$'
        )) {
        # The runtime intentionally derives its version from the same module manifest.
        $runtimeVersion = $manifestVersion
    }
    else {
        throw (
            'Unable to verify ICVersion. Use a version literal or derive it from ' +
            '[string]$moduleManifestData.ModuleVersion.'
        )
    }

    if ($runtimeVersion -ne $manifestVersion) {
        throw (
            "Runtime version '{0}' does not match module manifest version '{1}'." -f
            $runtimeVersion,
            $manifestVersion
        )
    }

    $changelogContent = Get-Content -LiteralPath $changelogPath -Raw -ErrorAction Stop
    $changelogPattern = '(?m)^##\s+\[{0}\](?:\s|$)' -f
        [regex]::Escape($manifestVersion.ToString())

    if (-not [regex]::IsMatch($changelogContent, $changelogPattern)) {
        throw (
            "CHANGELOG.md has no release heading for module version '{0}'." -f
            $manifestVersion
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedTag)) {
        $expectedReleaseTag = "v$manifestVersion"
        if ($ExpectedTag -ne $expectedReleaseTag) {
            throw (
                "Release tag '{0}' does not match module version '{1}'." -f
                $ExpectedTag,
                $expectedReleaseTag
            )
        }
    }

    Write-Verbose (
        "Version consistency verified: manifest, runtime, changelog{0} = {1}." -f
        $(if ([string]::IsNullOrWhiteSpace($ExpectedTag)) { '' } else { ', tag' }),
        $manifestVersion
    )

    $manifestVersion
}

function Get-PackageSmokeEngine {
    [CmdletBinding()]
    param()

    if ($env:OS -ne 'Windows_NT') {
        throw 'Release-package smoke tests require Windows.'
    }

    $windowsPowerShellPath = Join-Path `
        $env:SystemRoot `
        'System32/WindowsPowerShell/v1.0/powershell.exe'
    $powerShellCoreCommand = Get-Command `
        -Name 'pwsh.exe' `
        -CommandType Application `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not (Test-Path -LiteralPath $windowsPowerShellPath -PathType Leaf)) {
        throw "Windows PowerShell 5.1 was not found at '$windowsPowerShellPath'."
    }

    if ($null -eq $powerShellCoreCommand) {
        throw 'PowerShell 7 (pwsh.exe) is required for release-package smoke tests.'
    }

    @(
        [pscustomobject]@{
            Name = 'WindowsPowerShell'
            Path = $windowsPowerShellPath
        }
        [pscustomobject]@{
            Name = 'PowerShell'
            Path = $powerShellCoreCommand.Source
        }
    )
}

function Test-PackageChecksum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Package
    )

    $sidecar = (
        Get-Content -LiteralPath $Package.ChecksumPath -Raw -ErrorAction Stop
    ).Trim()
    $sidecarMatch = [regex]::Match(
        $sidecar,
        '^(?<Hash>[0-9a-fA-F]{64})  (?<File>[^\\/]+)$'
    )

    if (-not $sidecarMatch.Success) {
        throw "Invalid SHA-256 sidecar format: $($Package.ChecksumPath)"
    }

    $archiveName = Split-Path -Leaf $Package.ArchivePath
    if ($sidecarMatch.Groups['File'].Value -ne $archiveName) {
        throw (
            "Checksum sidecar names '{0}', expected '{1}'." -f
            $sidecarMatch.Groups['File'].Value,
            $archiveName
        )
    }

    $actualHash = (
        Get-FileHash -LiteralPath $Package.ArchivePath -Algorithm SHA256
    ).Hash
    if ($actualHash -ne $sidecarMatch.Groups['Hash'].Value) {
        throw "Release archive checksum verification failed: $archiveName"
    }

    Write-Verbose "Release archive checksum verified: $($actualHash.ToLowerInvariant())"
}

function Test-ReleasePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Package,

        [Parameter(Mandatory)]
        [version]$ExpectedVersion
    )

    Test-PackageChecksum -Package $Package

    $temporaryBase = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()
    ).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $smokeRoot = Join-Path `
        $temporaryBase `
        ("incident-capsule-package-{0}" -f [guid]::NewGuid().ToString('N'))
    $resolvedSmokeRoot = [System.IO.Path]::GetFullPath($smokeRoot)

    if (-not $resolvedSmokeRoot.StartsWith(
            $temporaryBase + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Refusing to use package smoke path outside the temporary directory: $resolvedSmokeRoot"
    }

    New-Item -ItemType Directory -Path $resolvedSmokeRoot -Force | Out-Null

    try {
        $extractRoot = Join-Path $resolvedSmokeRoot 'extracted'
        Expand-Archive `
            -LiteralPath $Package.ArchivePath `
            -DestinationPath $extractRoot `
            -Force

        $packageRoot = Join-Path $extractRoot $Package.PackageRootName
        $topLevelItems = @(Get-ChildItem -LiteralPath $extractRoot -Force)

        if ($topLevelItems.Count -ne 1 -or
            -not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
            throw (
                "Release archive must contain exactly one root directory named '{0}'." -f
                $Package.PackageRootName
            )
        }

        foreach ($engine in @(Get-PackageSmokeEngine)) {
            $smokeOutputPath = Join-Path $resolvedSmokeRoot $engine.Name
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-ExecutionPolicy'
                'Bypass'
                '-File'
                $packageSmokeScript
                '-PackageRoot'
                $packageRoot
                '-OutputPath'
                $smokeOutputPath
                '-ExpectedVersion'
                $ExpectedVersion.ToString()
            )

            Write-Verbose "Smoke-testing extracted package with $($engine.Name): $($engine.Path)"
            $smokeOutput = @(& $engine.Path @arguments)
            $exitCode = $LASTEXITCODE

            if ($smokeOutput.Count -gt 0) {
                Write-Verbose ($smokeOutput | Out-String)
            }

            if ($exitCode -ne 0) {
                throw (
                    "Package smoke test failed in {0} with exit code {1}." -f
                    $engine.Name,
                    $exitCode
                )
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $resolvedSmokeRoot) {
            Remove-Item -LiteralPath $resolvedSmokeRoot -Recurse -Force
        }
    }
}

function New-ReleasePackage {
    [CmdletBinding()]
    param(
        [string]$ExpectedTag
    )

    $versionObject = Test-ProjectVersion -ExpectedTag $ExpectedTag
    $version = $versionObject.ToString()
    $packageRootName = "incident-capsule-$version"
    $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputPathPrefix = $resolvedOutputPath.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $stagingRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $resolvedOutputPath $packageRootName)
    )

    if (-not $stagingRoot.StartsWith(
            $outputPathPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Refusing to stage a release outside the build output: $stagingRoot"
    }

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

    $archivePath = Join-Path $resolvedOutputPath "$packageRootName.zip"
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    Compress-Archive -LiteralPath $stagingRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
    $sidecarPath = "$archivePath.sha256"
    "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path -Leaf $archivePath) |
        Set-Content -LiteralPath $sidecarPath -Encoding ASCII

    $package = [pscustomobject]@{
        Version      = $version
        PackageRootName = $packageRootName
        ArchivePath  = $archivePath
        ChecksumPath = $sidecarPath
        SHA256       = $hash.Hash
    }

    Test-ReleasePackage -Package $package -ExpectedVersion $versionObject
    $package
}

if ($Task -in @('Clean', 'All')) {
    Remove-BuildOutput
}
elseif (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

if ($Task -in @('Test', 'All')) {
    Invoke-RepositoryTests
}

if ($Task -in @('Analyze', 'All')) {
    Invoke-StaticAnalysis
}

if ($Task -in @('Package', 'All')) {
    New-ReleasePackage -ExpectedTag $ReleaseTag
}

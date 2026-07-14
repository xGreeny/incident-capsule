Describe 'Release package launcher' {
    It 'loads the module beside the launcher in a self-contained package' {
        $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $repositoryLauncher = Join-Path $repositoryRoot 'tools/Invoke-IncidentCapsule.ps1'
        $repositoryManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
        $packageRoot = Join-Path $TestDrive 'incident-capsule-test'
        $packageModuleRoot = Join-Path $packageRoot 'IncidentCapsule'
        New-Item -ItemType Directory -Path $packageModuleRoot -Force | Out-Null

        Copy-Item `
            -LiteralPath $repositoryLauncher `
            -Destination (Join-Path $packageRoot 'Invoke-IncidentCapsule.ps1')

        @'
function Invoke-IncidentCapsule {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [string]$CaseId,
        [string]$Operator,
        [Alias('Profile')]
        [string]$CollectionProfile,
        [string]$ConfigurationPath,
        [string[]]$Collectors,
        [string[]]$ExcludeCollector,
        [switch]$NoCompression,
        [switch]$RemoveWorkingDirectory
    )

    [pscustomobject]@{
        ModuleBase        = $PSScriptRoot
        OutputPath        = $OutputPath
        CaseId            = $CaseId
        CollectionProfile = $CollectionProfile
        Collectors        = $Collectors
        NoCompression     = [bool]$NoCompression
    }
}

Export-ModuleMember -Function Invoke-IncidentCapsule
'@ | Set-Content `
            -LiteralPath (Join-Path $packageModuleRoot 'IncidentCapsule.psm1') `
            -Encoding UTF8

        @'
@{
    RootModule        = 'IncidentCapsule.psm1'
    ModuleVersion     = '9.9.9'
    GUID              = '50e837fa-737e-45ae-9522-8ef6a9cd1c01'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-IncidentCapsule')
}
'@ | Set-Content `
            -LiteralPath (Join-Path $packageModuleRoot 'IncidentCapsule.psd1') `
            -Encoding UTF8

        Remove-Module -Name IncidentCapsule -Force -ErrorAction SilentlyContinue

        try {
            $result = & (Join-Path $packageRoot 'Invoke-IncidentCapsule.ps1') `
                -OutputPath (Join-Path $TestDrive 'output') `
                -CaseId 'PACKAGE-TEST' `
                -Profile Minimal `
                -Collectors System `
                -NoCompression

            $result.ModuleBase | Should -Be $packageModuleRoot
            $result.CaseId | Should -Be 'PACKAGE-TEST'
            $result.CollectionProfile | Should -Be 'Minimal'
            $result.Collectors | Should -Be @('System')
            $result.NoCompression | Should -BeTrue
        }
        finally {
            Remove-Module -Name IncidentCapsule -Force -ErrorAction SilentlyContinue
            Import-Module $repositoryManifest -Force
        }
    }

    It 'reports every searched location when no module is present' {
        $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $repositoryLauncher = Join-Path $repositoryRoot 'tools/Invoke-IncidentCapsule.ps1'
        $emptyPackageRoot = Join-Path $TestDrive 'empty-package'
        New-Item -ItemType Directory -Path $emptyPackageRoot -Force | Out-Null
        $launcherPath = Join-Path $emptyPackageRoot 'Invoke-IncidentCapsule.ps1'
        Copy-Item -LiteralPath $repositoryLauncher -Destination $launcherPath

        {
            & $launcherPath -Collectors System -NoCompression
        } | Should -Throw '*module manifest was not found*Searched*'
    }
}

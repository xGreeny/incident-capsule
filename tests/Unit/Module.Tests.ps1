BeforeAll {
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
    Import-Module $moduleManifest -Force
}

Describe 'IncidentCapsule module' {
    It 'has a valid module manifest' {
        { Test-ModuleManifest -Path $moduleManifest -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports exactly the supported public commands' {
        $commands = @(Get-Command -Module IncidentCapsule | Select-Object -ExpandProperty Name | Sort-Object)
        $commands | Should -Be @(
            'Compare-IncidentCapsule',
            'Export-IncidentCapsuleData',
            'Get-IncidentCapsuleProfile',
            'Invoke-IncidentCapsule',
            'Test-IncidentCapsuleIntegrity',
            'Test-IncidentCapsuleReadiness'
        )
    }

    It 'declares PowerShell 5.1 compatibility' {
        $manifest = Test-ModuleManifest -Path $moduleManifest
        $manifest.PowerShellVersion | Should -Be ([version]'5.1')
    }

    It 'exposes three documented profiles' {
        $profiles = @(Get-IncidentCapsuleProfile)
        $profiles.Count | Should -Be 3
        $profiles.Name | Should -Be @('Minimal', 'Standard', 'Extended')
        @($profiles | Where-Object { [string]::IsNullOrWhiteSpace($_.Description) }).Count | Should -Be 0
    }

    It 'exposes each complete profile configuration' {
        $profileResult = Get-IncidentCapsuleProfile -Name Standard
        $profileResult.Configuration.Count | Should -BeGreaterThan 20
        foreach ($key in $profileResult.Configuration.Keys) {
            $profileResult.PSObject.Properties.Name | Should -Contain $key
        }
        $profileResult.MaximumCapsuleBytes | Should -Be $profileResult.Configuration.MaximumCapsuleBytes
        $profileResult.DataHandlingProfile | Should -Be 'Full'
    }
}

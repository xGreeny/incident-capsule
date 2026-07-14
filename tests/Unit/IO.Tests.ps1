$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$moduleManifest = Join-Path $repositoryRoot 'src/IncidentCapsule/IncidentCapsule.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Describe 'Incident Capsule IO helpers' {
    InModuleScope IncidentCapsule {
        It 'creates deterministic short hashes' {
            Get-ICShortHash -Value 'same value' | Should -Be (Get-ICShortHash -Value 'same value')
            Get-ICShortHash -Value 'same value' | Should -Not -Be (Get-ICShortHash -Value 'different value')
        }

        It 'sanitizes unsafe filename characters and bounds length' {
            $safe = ConvertTo-ICSafeFileName -Value 'Security/Log:*?<>| with spaces' -MaximumLength 28
            $safe.Length | Should -BeLessOrEqual 28
            $safe | Should -Not -Match '[/\\:*?<>|\s]'
        }

        It 'returns a forward-slash relative path' {
            $base = Join-Path $TestDrive 'root'
            $path = Join-Path $base 'evidence/system/test.json'
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            Set-Content -LiteralPath $path -Value '{}'
            Get-ICRelativePath -BasePath $base -Path $path | Should -Be 'evidence/system/test.json'
        }

        It 'writes UTF-8 without a byte-order mark' {
            $path = Join-Path $TestDrive 'utf8.txt'
            Write-ICUtf8File -Path $path -Content 'capsule' | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes[0] | Should -Not -Be 0xEF
            [System.IO.File]::ReadAllText($path) | Should -Be 'capsule'
        }


        It 'replaces an existing file without leaving a temporary artifact' {
            $path = Join-Path $TestDrive 'atomic.txt'
            Write-ICUtf8File -Path $path -Content 'first' | Out-Null
            Write-ICUtf8File -Path $path -Content 'second' | Out-Null
            [System.IO.File]::ReadAllText($path) | Should -Be 'second'
            @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp' -Force).Count | Should -Be 0
        }

        It 'prefixes spreadsheet formula values in derived CSV output' {
            $path = Join-Path $TestDrive 'safe.csv'
            $rows = @([pscustomobject]@{ Name = '=2+2'; Safe = 'value' })
            Write-ICCsvFile -Path $path -InputObject $rows -SpreadsheetSafe $true | Out-Null
            $content = Get-Content -LiteralPath $path -Raw
            $content | Should -Match "'=2\+2"
        }
    }
}

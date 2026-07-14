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

        It 'atomically replaces an existing file without leaving staging artifacts' {
            $path = Join-Path $TestDrive 'atomic.txt'
            Write-ICUtf8File -Path $path -Content 'first' | Out-Null
            Write-ICUtf8File -Path $path -Content 'second' | Out-Null

            [System.IO.File]::ReadAllText($path) | Should -Be 'second'
            @(Get-ChildItem -LiteralPath $TestDrive -Force | Where-Object Name -Match '\.(partial|backup)$').Count | Should -Be 0
        }

        It 'neutralizes spreadsheet formulas in CSV without mutating source data' {
            $row = [pscustomobject]@{
                Name   = 'sample'
                Value  = '=cmd|'' /C calc''!A0'
                Number = -1
            }
            $path = Join-Path $TestDrive 'safe.csv'
            Write-ICCsvFile -Path $path -InputObject @($row) | Out-Null

            $imported = Import-Csv -LiteralPath $path
            $imported.Value | Should -Be "'=cmd|' /C calc'!A0"
            $imported.Number | Should -Be '-1'
            $row.Value | Should -Be '=cmd|'' /C calc''!A0'
        }

        It 'retains the released SpreadsheetSafe switch and supports dictionary rows' {
            $unsafePath = Join-Path $TestDrive 'unsafe.csv'
            $safePath = Join-Path $TestDrive 'dictionary-safe.csv'
            $row = [ordered]@{ Name = 'sample'; Value = '  @SUM(A1:A2)' }

            Write-ICCsvFile -Path $unsafePath -InputObject @($row) -SpreadsheetSafe $false | Out-Null
            Write-ICCsvFile -Path $safePath -InputObject @($row) -SpreadsheetSafe $true | Out-Null

            (Import-Csv -LiteralPath $unsafePath).Value | Should -Be '  @SUM(A1:A2)'
            (Import-Csv -LiteralPath $safePath).Value | Should -Be "'  @SUM(A1:A2)"
            $row.Value | Should -Be '  @SUM(A1:A2)'
        }

        It 'terminates native commands that exceed the configured timeout' {
            $hostExecutable = (Get-Process -Id $PID).Path
            $context = [pscustomobject]@{
                Configuration = [ordered]@{
                    NativeCommandTimeoutSeconds = 1
                    MaximumNativeOutputBytes    = 4096
                }
            }

            $result = Invoke-ICNativeCommand `
                -FilePath $hostExecutable `
                -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 5') `
                -Context $context

            $result.TimedOut | Should -BeTrue
            $result.Error | Should -Match 'timed out'
        }

        It 'bounds captured native output and reports truncation' {
            $hostExecutable = (Get-Process -Id $PID).Path
            $result = Invoke-ICNativeCommand `
                -FilePath $hostExecutable `
                -ArgumentList @('-NoProfile', '-Command', '[Console]::Out.Write("x" * 20000)') `
                -TimeoutSeconds 10 `
                -MaximumOutputBytes 1024

            $result.OutputTruncated | Should -BeTrue
            $result.OutputBytes | Should -Be 1024
            $result.Error | Should -Match 'output limit'
        }
    }
}

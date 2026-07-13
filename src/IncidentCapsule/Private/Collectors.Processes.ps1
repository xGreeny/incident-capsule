function Get-ICProcessEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $userByProcessId = @{}

    try {
        foreach ($process in Get-Process -IncludeUserName -ErrorAction Stop) {
            $userByProcessId[[int]$process.Id] = $process.UserName
        }
    }
    catch {
        Add-ICCollectorWarning -List $warnings -Message "Process owners are partial: $($_.Exception.Message)"
    }

    $processes = @()
    try {
        $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
            $pidValue = [int]$_.ProcessId
            [pscustomobject][ordered]@{
                ProcessId = $pidValue
                ParentProcessId = [int]$_.ParentProcessId
                Name = $_.Name
                ExecutablePath = $_.ExecutablePath
                CommandLine = if ($Context.Configuration.IncludeProcessCommandLines) { $_.CommandLine } else { $null }
                Owner = if ($userByProcessId.ContainsKey($pidValue)) { $userByProcessId[$pidValue] } else { $null }
                SessionId = $_.SessionId
                CreationDateUtc = ConvertTo-ICIso8601 -Value $_.CreationDate
                ThreadCount = $_.ThreadCount
                HandleCount = $_.HandleCount
                WorkingSetSize = $_.WorkingSetSize
                KernelModeTime = $_.KernelModeTime
                UserModeTime = $_.UserModeTime
            }
        } | Sort-Object ProcessId)
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Process inventory: $($_.Exception.Message)" }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Processes -RelativePath 'evidence/processes/processes.json' -Data $processes -Csv)

    $hashRecords = @()
    if ($Context.Configuration.HashProcessExecutables) {
        $paths = @($processes.ExecutablePath | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique | Select-Object -First $Context.Configuration.MaximumExecutableHashes)
        $hashRecords = @($paths | ForEach-Object {
            $path = [string]$_
            $hash = $null
            $signatureStatus = $null
            $signer = $null
            $errorMessage = $null
            try {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                    if (Test-ICCommandAvailable -Name 'Get-AuthenticodeSignature') {
                        $signature = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
                        $signatureStatus = $signature.Status.ToString()
                        if ($null -ne $signature.SignerCertificate) {
                            $signer = $signature.SignerCertificate.Subject
                        }
                    }
                }
                else {
                    $errorMessage = 'Path is not accessible or no longer exists.'
                }
            }
            catch { $errorMessage = $_.Exception.Message }

            [pscustomobject][ordered]@{
                Path = $path
                SHA256 = $hash
                SignatureStatus = $signatureStatus
                SignerSubject = $signer
                Error = $errorMessage
            }
        })
        Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Processes -RelativePath 'evidence/processes/executable-hashes.json' -Data $hashRecords -Csv)
    }

    $uniqueImages = @($processes.ExecutablePath | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique).Count
    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        ProcessCount = $processes.Count
        UniqueExecutablePaths = $uniqueImages
        ExecutablesHashed = $hashRecords.Count
        CommandLinesIncluded = [bool]$Context.Configuration.IncludeProcessCommandLines
    })
}

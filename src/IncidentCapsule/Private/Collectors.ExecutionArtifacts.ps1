function ConvertFrom-ICRot13 {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    $characters = $Value.ToCharArray()
    for ($index = 0; $index -lt $characters.Length; $index++) {
        $code = [int]$characters[$index]
        if ($code -ge 65 -and $code -le 90) {
            $characters[$index] = [char]((($code - 65 + 13) % 26) + 65)
        }
        elseif ($code -ge 97 -and $code -le 122) {
            $characters[$index] = [char]((($code - 97 + 13) % 26) + 97)
        }
    }
    return -join $characters
}

function ConvertTo-ICByteArray {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }
    # The unary comma keeps the byte[] intact across the return: without it
    # PowerShell enumerates the array and the caller receives object[], which is
    # exactly why the AppCompatCache export was skipped on every host. A value
    # that PowerShell already surfaced as object[] (observed with PowerShell 7.5
    # on Windows 11) is cast rather than rejected.
    if ($Value -is [byte[]]) {
        return , $Value
    }
    if ($Value -is [System.Array]) {
        try { return , ([byte[]]$Value) } catch { return $null }
    }
    return $null
}

function ConvertFrom-ICFileTimeUtc {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$FileTime
    )

    try {
        $value = [int64]$FileTime
        if ($value -le 0) {
            return $null
        }
        $timestamp = [datetime]::FromFileTimeUtc($value)
        if ($timestamp.Year -lt 1990 -or $timestamp -gt [datetime]::UtcNow.AddDays(1)) {
            return $null
        }
        return $timestamp.ToString('o')
    }
    catch {
        return $null
    }
}

function Get-ICExecutionArtifactEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $maximumPrefetchFiles = [int](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'MaximumPrefetchFiles' -Default 512)
    $maximumArtifactBytes = [int64](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'MaximumArtifactFileBytes' -Default 33554432L)

    $prefetchRecords = New-Object System.Collections.ArrayList
    $prefetchCopied = 0
    $prefetchFound = 0
    $prefetchDirectory = Join-Path $env:SystemRoot 'Prefetch'
    if (Test-Path -LiteralPath $prefetchDirectory -PathType Container) {
        try {
            $prefetchFiles = @(
                Get-ChildItem -LiteralPath $prefetchDirectory -Filter '*.pf' -File -Force -ErrorAction Stop |
                    Sort-Object LastWriteTimeUtc -Descending
            )
            $prefetchFound = $prefetchFiles.Count
            $destinationDirectory = Join-Path $Context.RootPath 'evidence\execution\prefetch'
            foreach ($prefetchFile in $prefetchFiles) {
                $record = Get-ICFileMetadata -Path $prefetchFile.FullName
                $copied = $false
                $capsulePath = $null
                if ($prefetchCopied -lt $maximumPrefetchFiles -and [int64]$prefetchFile.Length -le $maximumArtifactBytes) {
                    try {
                        [void][System.IO.Directory]::CreateDirectory($destinationDirectory)
                        $destinationPath = Join-Path $destinationDirectory (ConvertTo-ICSafeFileName -Value $prefetchFile.Name)
                        [System.IO.File]::Copy($prefetchFile.FullName, $destinationPath, $false)
                        Add-ICOutputFiles -List $files -Path @($destinationPath)
                        $capsulePath = Get-ICRelativePath -BasePath $Context.RootPath -Path $destinationPath
                        $copied = $true
                        $prefetchCopied++
                    }
                    catch { Add-ICCollectorWarning -List $warnings -Message "Prefetch copy '$($prefetchFile.Name)': $($_.Exception.Message)" }
                }
                $record | Add-Member -NotePropertyName Copied -NotePropertyValue $copied -Force
                $record | Add-Member -NotePropertyName CapsulePath -NotePropertyValue $capsulePath -Force
                [void]$prefetchRecords.Add($record)
            }
            if ($prefetchFound -gt $prefetchCopied) {
                Add-ICCollectorWarning -List $warnings -Message ("Prefetch copy bounded: {0} of {1} file(s) copied (MaximumPrefetchFiles={2}, MaximumArtifactFileBytes={3})." -f $prefetchCopied, $prefetchFound, $maximumPrefetchFiles, $maximumArtifactBytes)
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Prefetch inventory: $($_.Exception.Message)" }
    }
    else {
        Add-ICCollectorWarning -List $warnings -Message "Prefetch directory '$prefetchDirectory' is unavailable; prefetch can be disabled on this system."
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector ExecutionArtifacts -RelativePath 'evidence/execution/prefetch-files.json' -Data @($prefetchRecords) -Csv)

    $appCompatCacheBytes = 0
    try {
        $appCompatKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
        $appCompatRecord = [ordered]@{
            SourceKey   = $appCompatKey
            ValueName   = 'AppCompatCache'
            LengthBytes = $null
            SHA256      = $null
            CapsulePath = $null
        }
        $properties = Get-ItemProperty -LiteralPath $appCompatKey -ErrorAction Stop
        $rawValue = Get-ICPropertyValue -InputObject $properties -Name 'AppCompatCache'
        $rawCache = ConvertTo-ICByteArray -Value $rawValue
        if ($rawCache -is [byte[]] -and $rawCache.Length -gt 0) {
            $binaryPath = Join-Path $Context.RootPath 'evidence\execution\appcompatcache.bin'
            [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $binaryPath))
            [System.IO.File]::WriteAllBytes($binaryPath, $rawCache)
            Add-ICOutputFiles -List $files -Path @($binaryPath)
            $appCompatCacheBytes = $rawCache.Length
            $appCompatRecord.LengthBytes = $rawCache.Length
            $appCompatRecord.SHA256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            $appCompatRecord.CapsulePath = Get-ICRelativePath -BasePath $Context.RootPath -Path $binaryPath
        }
        else {
            $reason = if ($null -eq $rawValue) {
                "value 'AppCompatCache' was not found under '$appCompatKey'"
            }
            elseif ($null -eq $rawCache) {
                "value 'AppCompatCache' has unconvertible type '$($rawValue.GetType().FullName)'"
            }
            else {
                "value 'AppCompatCache' exists but is empty"
            }
            Add-ICCollectorWarning -List $warnings -Message "AppCompatCache snapshot: $reason."
        }
        Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector ExecutionArtifacts -RelativePath 'evidence/execution/appcompatcache.json' -Data ([pscustomobject]$appCompatRecord))
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "AppCompatCache snapshot: $($_.Exception.Message)" }

    $bamEntries = New-Object System.Collections.ArrayList
    foreach ($bamRoot in @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    )) {
        if (-not (Test-Path -LiteralPath $bamRoot)) {
            continue
        }
        try {
            foreach ($sidKey in Get-ChildItem -LiteralPath $bamRoot -ErrorAction Stop) {
                $sid = Split-Path -Leaf $sidKey.Name
                try {
                    $properties = Get-ItemProperty -LiteralPath $sidKey.PSPath -ErrorAction Stop
                    foreach ($property in $properties.PSObject.Properties) {
                        if ($property.Name -notmatch '\\' -or $property.Value -isnot [byte[]] -or $property.Value.Length -lt 8) {
                            continue
                        }
                        [void]$bamEntries.Add([pscustomobject][ordered]@{
                            Sid              = $sid
                            ExecutablePath   = [string]$property.Name
                            LastExecutionUtc = ConvertFrom-ICFileTimeUtc -FileTime ([System.BitConverter]::ToInt64($property.Value, 0))
                            SourceKey        = [string]$sidKey.Name
                        })
                    }
                }
                catch { Add-ICCollectorWarning -List $warnings -Message "BAM settings '$sid': $($_.Exception.Message)" }
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "BAM root '$bamRoot': $($_.Exception.Message)" }
        break
    }
    if ($bamEntries.Count -eq 0) {
        Add-ICCollectorWarning -List $warnings -Message 'Background Activity Moderator (BAM) execution records are unavailable on this system.'
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector ExecutionArtifacts -RelativePath 'evidence/execution/bam-entries.json' -Data @($bamEntries | Sort-Object Sid, ExecutablePath) -Csv)

    $userAssistEntries = New-Object System.Collections.ArrayList
    try {
        foreach ($hive in Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop) {
            $sidName = Split-Path -Leaf $hive.Name
            if ($sidName -match '_Classes$') {
                continue
            }
            $userAssistRoot = "Registry::HKEY_USERS\$sidName\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            if (-not (Test-Path -LiteralPath $userAssistRoot)) {
                continue
            }
            try {
                foreach ($namespaceKey in Get-ChildItem -LiteralPath $userAssistRoot -ErrorAction Stop) {
                    $countPath = Join-Path $namespaceKey.PSPath 'Count'
                    if (-not (Test-Path -LiteralPath $countPath)) {
                        continue
                    }
                    $properties = Get-ItemProperty -LiteralPath $countPath -ErrorAction Stop
                    foreach ($property in $properties.PSObject.Properties) {
                        if ($property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$' -or $property.Value -isnot [byte[]]) {
                            continue
                        }
                        $bytes = [byte[]]$property.Value
                        $runCount = if ($bytes.Length -ge 8) { [System.BitConverter]::ToInt32($bytes, 4) } else { $null }
                        $lastExecution = if ($bytes.Length -ge 68) { ConvertFrom-ICFileTimeUtc -FileTime ([System.BitConverter]::ToInt64($bytes, 60)) } else { $null }
                        [void]$userAssistEntries.Add([pscustomobject][ordered]@{
                            Sid              = $sidName
                            GuidNamespace    = Split-Path -Leaf $namespaceKey.Name
                            DecodedName      = ConvertFrom-ICRot13 -Value ([string]$property.Name)
                            RunCount         = $runCount
                            LastExecutionUtc = $lastExecution
                            ValueLength      = $bytes.Length
                        })
                    }
                }
            }
            catch { Add-ICCollectorWarning -List $warnings -Message "UserAssist hive '$sidName': $($_.Exception.Message)" }
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "UserAssist enumeration: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector ExecutionArtifacts -RelativePath 'evidence/execution/userassist-entries.json' -Data @($userAssistEntries | Sort-Object Sid, DecodedName) -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        PrefetchFilesFound  = $prefetchFound
        PrefetchFilesCopied = $prefetchCopied
        AppCompatCacheBytes = $appCompatCacheBytes
        BamEntries          = $bamEntries.Count
        UserAssistEntries   = $userAssistEntries.Count
    })
}

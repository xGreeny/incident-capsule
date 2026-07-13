function Get-ICPropertyValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return $property.Value
}

function ConvertTo-ICIso8601 {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([datetime]$Value).ToUniversalTime().ToString('o')
    }
    catch {
        return [string]$Value
    }
}

function Get-ICShortHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [ValidateRange(4, 32)]
        [int]$Length = 10
    )

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $algorithm.ComputeHash($bytes)
        $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
        return $hex.Substring(0, $Length)
    }
    finally {
        $algorithm.Dispose()
    }
}

function ConvertTo-ICSafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [ValidateRange(8, 200)]
        [int]$MaximumLength = 100
    )

    $candidate = $Value.Trim()
    foreach ($character in [System.IO.Path]::GetInvalidFileNameChars()) {
        $candidate = $candidate.Replace([string]$character, '_')
    }

    $candidate = $candidate -replace '[\\/:*?"<>|\s]+', '_'
    $candidate = $candidate.Trim('.', '_')
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = 'unnamed'
    }

    if ($candidate.Length -gt $MaximumLength) {
        $digest = Get-ICShortHash -Value $Value -Length 10
        $prefixLength = $MaximumLength - $digest.Length - 1
        $candidate = '{0}-{1}' -f $candidate.Substring(0, $prefixLength), $digest
    }

    return $candidate
}

function Get-ICRelativePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $baseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char]'\', [char]'/')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $prefix = $baseFull + [System.IO.Path]::DirectorySeparatorChar

    if (-not $pathFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$pathFull' is outside base path '$baseFull'."
    }

    return $pathFull.Substring($prefix.Length).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
}

function Write-ICUtf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowEmptyString()]
        [string]$Content
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
    return $Path
}

function Write-ICJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object]$InputObject,

        [ValidateRange(2, 100)]
        [int]$Depth = 12
    )

    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth
    return Write-ICUtf8File -Path $Path -Content ($json + [Environment]::NewLine)
}

function Write-ICCsvFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object[]]$InputObject
    )

    $items = @($InputObject)
    $content = if ($items.Count -gt 0) {
        ($items | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
    }
    else {
        ''
    }

    return Write-ICUtf8File -Path $Path -Content ($content + [Environment]::NewLine)
}

function Write-ICLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Component,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if ($Context.Frozen) {
        return
    }

    $safeMessage = $Message -replace "`r?`n", ' | '
    $line = '{0} [{1}] [{2}] {3}' -f [datetime]::UtcNow.ToString('o'), $Level, $Component, $safeMessage
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($line + [Environment]::NewLine)
    $stream = New-Object System.IO.FileStream($Context.LogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function New-ICCollectorResultData {
    [CmdletBinding()]
    param(
        [object[]]$OutputFiles = @(),
        [string[]]$Warnings = @(),
        [System.Collections.IDictionary]$Metrics = ([ordered]@{})
    )

    return [pscustomobject][ordered]@{
        OutputFiles = @($OutputFiles)
        Warnings    = @($Warnings)
        Metrics     = $Metrics
    }
}

function Export-ICCollectorData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$Collector,

        [Parameter(Mandatory)]
        [string]$RelativePath,

        [AllowNull()]
        [object]$Data,

        [switch]$Csv
    )

    $jsonPath = Join-Path $Context.RootPath ($RelativePath -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    $payload = [ordered]@{
        '$schema'      = $script:ICCollectorSchema
        schemaVersion  = $script:ICSchemaVersion
        capsuleId      = $Context.CapsuleId
        collector      = $Collector
        capturedAtUtc  = [datetime]::UtcNow.ToString('o')
        host            = $Context.HostName
        data            = $Data
    }

    $written = New-Object System.Collections.ArrayList
    [void]$written.Add((Write-ICJsonFile -Path $jsonPath -InputObject $payload -Depth 20))

    if ($Csv) {
        $csvPath = [System.IO.Path]::ChangeExtension($jsonPath, '.csv')
        [void]$written.Add((Write-ICCsvFile -Path $csvPath -InputObject @($Data)))
    }

    return @($written)
}

function Test-ICCommandAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Invoke-ICNativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @()
    )

    $output = @()
    $exitCode = $null
    try {
        $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
        return [pscustomobject][ordered]@{
            FilePath  = $FilePath
            Arguments = @($ArgumentList)
            ExitCode  = $exitCode
            Output    = $output
            Error     = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            FilePath  = $FilePath
            Arguments = @($ArgumentList)
            ExitCode  = $exitCode
            Output    = $output
            Error     = $_.Exception.Message
        }
    }
}

function Export-ICNativeCommandOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$RelativePath,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @()
    )

    $result = Invoke-ICNativeCommand -FilePath $FilePath -ArgumentList $ArgumentList
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# capturedAtUtc: $([datetime]::UtcNow.ToString('o'))")
    $lines.Add("# command: $FilePath $($ArgumentList -join ' ')")
    $lines.Add("# exitCode: $($result.ExitCode)")
    if ($null -ne $result.Error) {
        $lines.Add("# error: $($result.Error)")
    }
    $lines.Add('')
    foreach ($line in $result.Output) {
        $lines.Add([string]$line)
    }

    $path = Join-Path $Context.RootPath ($RelativePath -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    [void](Write-ICUtf8File -Path $path -Content (($lines -join [Environment]::NewLine) + [Environment]::NewLine))

    return [pscustomobject][ordered]@{
        Path     = $path
        ExitCode = $result.ExitCode
        Error    = $result.Error
    }
}

function Get-ICRegistryValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [string[]]$ValueName
    )

    $results = New-Object System.Collections.ArrayList
    foreach ($registryPath in $Path) {
        if (-not (Test-Path -LiteralPath $registryPath)) {
            continue
        }

        try {
            $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
            $properties = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
            $names = if ($null -ne $ValueName -and $ValueName.Count -gt 0) {
                @($ValueName)
            }
            else {
                @($properties.PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' })
            }

            foreach ($name in $names) {
                $property = $properties.PSObject.Properties[$name]
                if ($null -eq $property) {
                    continue
                }

                $kind = $null
                try { $kind = $key.GetValueKind($name).ToString() } catch { $kind = $null }
                [void]$results.Add([pscustomobject][ordered]@{
                    Key       = $registryPath
                    ValueName = $name
                    ValueType = $kind
                    Data      = $property.Value
                })
            }
        }
        catch {
            [void]$results.Add([pscustomobject][ordered]@{
                Key       = $registryPath
                ValueName = $null
                ValueType = $null
                Data      = $null
                Error     = $_.Exception.Message
            })
        }
    }

    return @($results)
}

function Get-ICFileMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$Hash
    )

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $sha256 = $null
        if ($Hash -and -not $item.PSIsContainer) {
            try { $sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { $sha256 = $null }
        }

        return [pscustomobject][ordered]@{
            Path             = $item.FullName
            Name             = $item.Name
            IsDirectory      = [bool]$item.PSIsContainer
            Length           = if ($item.PSIsContainer) { $null } else { $item.Length }
            CreationTimeUtc  = ConvertTo-ICIso8601 -Value $item.CreationTimeUtc
            LastWriteTimeUtc = ConvertTo-ICIso8601 -Value $item.LastWriteTimeUtc
            Attributes       = [string]$item.Attributes
            SHA256           = $sha256
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Path  = $Path
            Error = $_.Exception.Message
        }
    }
}

function ConvertTo-ICHtml {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

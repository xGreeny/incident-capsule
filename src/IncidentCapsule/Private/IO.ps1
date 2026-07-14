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

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $temporaryPath = Join-Path $directory ('.{0}.{1}.partial' -f [System.IO.Path]::GetFileName($fullPath), [guid]::NewGuid().ToString('N'))
    $backupPath = Join-Path $directory ('.{0}.{1}.backup' -f [System.IO.Path]::GetFileName($fullPath), [guid]::NewGuid().ToString('N'))
    $stream = $null
    try {
        $bytes = $encoding.GetBytes($Content)
        $stream = New-Object System.IO.FileStream(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if ([System.IO.File]::Exists($fullPath)) {
            [System.IO.File]::Replace($temporaryPath, $fullPath, $backupPath)
            [System.IO.File]::Delete($backupPath)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $fullPath)
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
        if ([System.IO.File]::Exists($backupPath)) {
            if ([System.IO.File]::Exists($fullPath)) {
                [System.IO.File]::Delete($backupPath)
            }
            else {
                [System.IO.File]::Move($backupPath, $fullPath)
            }
        }
    }

    return $fullPath
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

function ConvertTo-ICSpreadsheetSafeValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -isnot [string]) {
        return $Value
    }

    $text = [string]$Value
    if ($text -match '^[\x00-\x20]*[=+\-@]') {
        return "'$text"
    }

    return $text
}

function ConvertTo-ICSpreadsheetSafeRow {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$InputObject,

        [bool]$SpreadsheetSafe = $true
    )

    $rows = New-Object System.Collections.ArrayList
    foreach ($item in @($InputObject)) {
        if ($null -eq $item) {
            [void]$rows.Add($null)
            continue
        }

        $row = [ordered]@{}
        if ($item -is [System.Collections.IDictionary]) {
            foreach ($key in $item.Keys) {
                $value = $item[$key]
                $row[[string]$key] = if ($SpreadsheetSafe) { ConvertTo-ICSpreadsheetSafeValue -Value $value } else { $value }
            }
        }
        else {
            foreach ($property in $item.PSObject.Properties) {
                if (-not $property.IsGettable -or $property.MemberType -notin @('NoteProperty', 'Property', 'AliasProperty', 'ScriptProperty')) {
                    continue
                }
                $row[$property.Name] = if ($SpreadsheetSafe) { ConvertTo-ICSpreadsheetSafeValue -Value $property.Value } else { $property.Value }
            }
        }

        if ($row.Count -eq 0) {
            $value = if ($SpreadsheetSafe) { ConvertTo-ICSpreadsheetSafeValue -Value $item } else { $item }
            [void]$rows.Add($value)
        }
        else {
            [void]$rows.Add([pscustomobject]$row)
        }
    }

    return @($rows)
}

function Write-ICCsvFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object[]]$InputObject,

        [bool]$SpreadsheetSafe = $true
    )

    $items = @(ConvertTo-ICSpreadsheetSafeRow -InputObject @($InputObject) -SpreadsheetSafe $SpreadsheetSafe)
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
        $spreadsheetSafe = $true
        if ($null -ne $Context.Configuration -and $Context.Configuration.Contains('SpreadsheetSafeCsv')) {
            $spreadsheetSafe = [bool]$Context.Configuration.SpreadsheetSafeCsv
        }
        [void]$written.Add((Write-ICCsvFile -Path $csvPath -InputObject @($Data) -SpreadsheetSafe $spreadsheetSafe))
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

        [string[]]$ArgumentList = @(),

        [AllowNull()]
        [object]$Context,

        [ValidateRange(0, 86400)]
        [int]$TimeoutSeconds = 0,

        [ValidateRange(0, 2147483647)]
        [int64]$MaximumOutputBytes = 0
    )

    if ($TimeoutSeconds -eq 0) {
        $configuration = Get-ICPropertyValue -InputObject $Context -Name 'Configuration'
        $TimeoutSeconds = [int](Get-ICPropertyValue -InputObject $configuration -Name 'NativeCommandTimeoutSeconds' -Default 120)
    }
    if ($MaximumOutputBytes -eq 0) {
        $configuration = Get-ICPropertyValue -InputObject $Context -Name 'Configuration'
        $MaximumOutputBytes = [int64](Get-ICPropertyValue -InputObject $configuration -Name 'MaximumNativeOutputBytes' -Default 16777216)
    }
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 86400) {
        throw 'Native command timeout must be between 1 and 86400 seconds.'
    }
    if ($MaximumOutputBytes -lt 1 -or $MaximumOutputBytes -gt 2147483647) {
        throw 'Native command output limit must be between 1 and 2147483647 bytes.'
    }

    $output = @()
    $exitCode = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($null -eq ('IncidentCapsule.Runtime.NativeCommandRunner' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IncidentCapsule.Runtime
{
    public sealed class NativeCommandCapture
    {
        public int? ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public bool TimedOut { get; set; }
        public bool OutputTruncated { get; set; }
        public long OutputBytes { get; set; }
    }

    internal sealed class BoundedCaptureState
    {
        private readonly object sync = new object();
        private readonly long maximumBytes;
        private long capturedBytes;

        internal readonly Process Process;
        internal bool LimitExceeded;

        internal BoundedCaptureState(Process process, long maximumBytes)
        {
            Process = process;
            this.maximumBytes = maximumBytes;
        }

        internal long CapturedBytes { get { lock (sync) { return capturedBytes; } } }

        internal void Copy(Stream source, MemoryStream destination)
        {
            byte[] buffer = new byte[8192];
            try
            {
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    int accepted;
                    bool terminate = false;
                    lock (sync)
                    {
                        long remaining = maximumBytes - capturedBytes;
                        accepted = remaining <= 0 ? 0 : (int)Math.Min((long)read, remaining);
                        capturedBytes += accepted;
                        if (accepted < read)
                        {
                            LimitExceeded = true;
                            terminate = true;
                        }
                    }

                    if (accepted > 0)
                    {
                        destination.Write(buffer, 0, accepted);
                    }
                    if (terminate)
                    {
                        try { Process.Kill(); } catch { }
                        break;
                    }
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }
    }

    public static class NativeCommandRunner
    {
        private static string QuoteArgument(string value)
        {
            if (value == null) { return "\"\""; }
            if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            {
                return value;
            }

            StringBuilder builder = new StringBuilder();
            builder.Append('"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                    builder.Append('"');
                    backslashes = 0;
                    continue;
                }
                builder.Append('\\', backslashes);
                backslashes = 0;
                builder.Append(character);
            }
            builder.Append('\\', backslashes * 2);
            builder.Append('"');
            return builder.ToString();
        }

        public static NativeCommandCapture Run(string filePath, string[] arguments, int timeoutSeconds, long maximumOutputBytes)
        {
            List<string> quoted = new List<string>();
            if (arguments != null)
            {
                foreach (string argument in arguments) { quoted.Add(QuoteArgument(argument)); }
            }

            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = filePath;
            info.Arguments = string.Join(" ", quoted.ToArray());
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;

            using (Process process = new Process())
            using (MemoryStream standardOutput = new MemoryStream())
            using (MemoryStream standardError = new MemoryStream())
            {
                process.StartInfo = info;
                if (!process.Start()) { throw new InvalidOperationException("Native process did not start."); }

                Encoding outputEncoding = process.StandardOutput.CurrentEncoding;
                Encoding errorEncoding = process.StandardError.CurrentEncoding;
                BoundedCaptureState state = new BoundedCaptureState(process, maximumOutputBytes);
                Task outputTask = Task.Factory.StartNew(
                    () => state.Copy(process.StandardOutput.BaseStream, standardOutput),
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
                Task errorTask = Task.Factory.StartNew(
                    () => state.Copy(process.StandardError.BaseStream, standardError),
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);

                bool exited = process.WaitForExit(checked(timeoutSeconds * 1000));
                bool timedOut = !exited;
                if (timedOut)
                {
                    try { process.Kill(); } catch { }
                }

                try
                {
                    if (!timedOut) { process.WaitForExit(); }
                    else { process.WaitForExit(5000); }
                }
                catch { }
                try { Task.WaitAll(new[] { outputTask, errorTask }, 5000); } catch { }

                int? exitCode = null;
                try { if (process.HasExited) { exitCode = process.ExitCode; } } catch { }

                return new NativeCommandCapture
                {
                    ExitCode = exitCode,
                    StandardOutput = outputEncoding.GetString(standardOutput.ToArray()),
                    StandardError = errorEncoding.GetString(standardError.ToArray()),
                    TimedOut = timedOut,
                    OutputTruncated = state.LimitExceeded,
                    OutputBytes = state.CapturedBytes
                };
            }
        }
    }
}
'@ -ErrorAction Stop
        }

        $capture = [IncidentCapsule.Runtime.NativeCommandRunner]::Run(
            $FilePath,
            @($ArgumentList),
            $TimeoutSeconds,
            $MaximumOutputBytes
        )
        $exitCode = $capture.ExitCode
        $capturedStreams = @($capture.StandardOutput; $capture.StandardError) |
            Where-Object { -not [string]::IsNullOrEmpty($_) }
        $combined = $capturedStreams -join [Environment]::NewLine
        if (-not [string]::IsNullOrEmpty($combined)) {
            $output = @([regex]::Split($combined.TrimEnd("`r", "`n"), '\r\n|\n|\r'))
        }

        $errorMessage = $null
        if ($capture.TimedOut) {
            $errorMessage = "Native command timed out after $TimeoutSeconds second(s)."
        }
        elseif ($capture.OutputTruncated) {
            $errorMessage = "Native command exceeded the $MaximumOutputBytes-byte output limit and was terminated."
        }

        return [pscustomobject][ordered]@{
            FilePath            = $FilePath
            Arguments           = @($ArgumentList)
            ExitCode            = $exitCode
            Output              = $output
            Error               = $errorMessage
            TimedOut            = [bool]$capture.TimedOut
            OutputTruncated     = [bool]$capture.OutputTruncated
            OutputBytes         = [int64]$capture.OutputBytes
            DurationMilliseconds = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 0)
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            FilePath            = $FilePath
            Arguments           = @($ArgumentList)
            ExitCode            = $exitCode
            Output              = $output
            Error               = $_.Exception.Message
            TimedOut            = $false
            OutputTruncated     = $false
            OutputBytes         = 0
            DurationMilliseconds = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 0)
        }
    }
    finally {
        $stopwatch.Stop()
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

    $result = Invoke-ICNativeCommand -FilePath $FilePath -ArgumentList $ArgumentList -Context $Context
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# capturedAtUtc: $([datetime]::UtcNow.ToString('o'))")
    $lines.Add("# command: $FilePath $($ArgumentList -join ' ')")
    $lines.Add("# exitCode: $($result.ExitCode)")
    $lines.Add("# timedOut: $($result.TimedOut)")
    $lines.Add("# outputTruncated: $($result.OutputTruncated)")
    $lines.Add("# outputBytes: $($result.OutputBytes)")
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
        Path            = $path
        ExitCode        = $result.ExitCode
        Error           = $result.Error
        TimedOut        = $result.TimedOut
        OutputTruncated = $result.OutputTruncated
        OutputBytes     = $result.OutputBytes
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

function New-ICReadinessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Code,

        [Parameter(Mandatory)]
        [ValidateSet('Platform', 'Output', 'Storage', 'Privileges', 'Commands', 'CIM', 'EventLogs')]
        [string]$Category,

        [Parameter(Mandatory)]
        [ValidateSet('Passed', 'Warning', 'Failed')]
        [string]$Status,

        [Parameter(Mandatory)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Message,

        [AllowNull()]
        [object]$Details
    )

    return [pscustomobject][ordered]@{
        PSTypeName = 'IncidentCapsule.ReadinessCheck'
        Code       = $Code
        Category   = $Category
        Status     = $Status
        Severity   = $Severity
        Message    = $Message
        Details    = $Details
    }
}

function Get-ICOutputProbeDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $candidate = $Path
    while (-not [string]::IsNullOrWhiteSpace($candidate)) {
        if (Test-Path -LiteralPath $candidate) {
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                return [pscustomobject]@{
                    Directory    = $candidate
                    BlockingPath = $null
                }
            }

            return [pscustomobject]@{
                Directory    = $null
                BlockingPath = $candidate
            }
        }

        $parent = Split-Path -Path $candidate -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $candidate) {
            break
        }
        $candidate = $parent
    }

    return [pscustomobject]@{
        Directory    = $null
        BlockingPath = $null
    }
}

function Test-ICOutputWritable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $probePath = Join-Path $Path ('.incident-capsule-readiness-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $probePath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $stream.WriteByte(0)
        return [pscustomobject]@{
            IsWritable = $true
            Error      = $null
        }
    }
    catch {
        return [pscustomobject]@{
            IsWritable = $false
            Error      = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if (Test-Path -LiteralPath $probePath -PathType Leaf) {
            Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-ICAvailableStorageByte {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $matchingDrive = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.Root) -and
                $fullPath.StartsWith([string]$_.Root, [System.StringComparison]::OrdinalIgnoreCase)
            } |
            Sort-Object { ([string]$_.Root).Length } -Descending |
            Select-Object -First 1

        if ($null -ne $matchingDrive -and $null -ne $matchingDrive.Free) {
            return [int64]$matchingDrive.Free
        }

        $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
        if (-not [string]::IsNullOrWhiteSpace($pathRoot)) {
            $driveInfo = New-Object System.IO.DriveInfo($pathRoot)
            if ($driveInfo.IsReady) {
                return [int64]$driveInfo.AvailableFreeSpace
            }
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-ICReadinessCommandName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $commandsByCollector = [ordered]@{
        System                = @('whoami.exe', 'w32tm.exe')
        Storage               = @('Get-BitLockerVolume', 'Get-SmbShare')
        Network               = @('Get-NetAdapter', 'Get-NetIPAddress', 'Get-NetRoute', 'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-NetNeighbor', 'ipconfig.exe', 'route.exe', 'arp.exe', 'netstat.exe')
        Sessions              = @('quser.exe', 'qwinsta.exe')
        LocalAccounts         = @('Get-LocalUser', 'Get-LocalGroup', 'Get-LocalGroupMember')
        ScheduledTasks        = @('Get-ScheduledTask', 'Get-ScheduledTaskInfo')
        Defender              = @('Get-MpComputerStatus')
        SecurityConfiguration = @('Get-NetFirewallProfile', 'Get-NetFirewallRule', 'auditpol.exe', 'netsh.exe', 'secedit.exe')
        Drivers               = @('driverquery.exe')
        EventLogs             = @('Get-WinEvent')
    }

    $commandNames = New-Object System.Collections.ArrayList
    foreach ($collectorName in @($Configuration.Collectors)) {
        if ($commandsByCollector.Contains($collectorName)) {
            foreach ($commandName in @($commandsByCollector[$collectorName])) {
                if ($commandName -notin $commandNames) {
                    [void]$commandNames.Add($commandName)
                }
            }
        }
    }

    if ('EventLogs' -in @($Configuration.Collectors) -and $Configuration.ExportEvtx -and 'wevtutil.exe' -notin $commandNames) {
        [void]$commandNames.Add('wevtutil.exe')
    }

    return @($commandNames)
}

function Get-ICCommandReadinessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $commandNames = @(Get-ICReadinessCommandName -Configuration $Configuration)
    if ($commandNames.Count -eq 0) {
        return @(New-ICReadinessCheck -Code 'COMMANDS_NOT_REQUIRED' -Category Commands -Status Passed -Severity Information -Message 'The selected collectors have no additional command prerequisites.' -Details $null)
    }

    $missing = @($commandNames | Where-Object { $null -eq (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
    if ($missing.Count -eq 0) {
        return @(New-ICReadinessCheck -Code 'COMMANDS_AVAILABLE' -Category Commands -Status Passed -Severity Information -Message 'All checked collector commands are available.' -Details ([pscustomobject][ordered]@{
            CheckedCommands = @($commandNames)
        }))
    }

    return @(New-ICReadinessCheck -Code 'OPTIONAL_COMMANDS_MISSING' -Category Commands -Status Warning -Severity Warning -Message 'Some collector integrations are unavailable; affected collectors can complete partially.' -Details ([pscustomobject][ordered]@{
        CheckedCommands = @($commandNames)
        MissingCommands = @($missing)
    }))
}

function Get-ICCimReadinessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $cimCollectors = @(
        'System', 'Storage', 'Processes', 'Services', 'Sessions', 'LocalAccounts',
        'Persistence', 'SecurityConfiguration', 'Hotfixes', 'Drivers'
    )
    $selectedCimCollectors = @($Configuration.Collectors | Where-Object { $_ -in $cimCollectors })
    if ($selectedCimCollectors.Count -eq 0) {
        return @(New-ICReadinessCheck -Code 'CIM_NOT_REQUIRED' -Category CIM -Status Passed -Severity Information -Message 'The selected collectors do not require CIM.' -Details $null)
    }

    if ($null -eq (Get-Command -Name 'Get-CimInstance' -ErrorAction SilentlyContinue)) {
        return @(New-ICReadinessCheck -Code 'CIM_COMMAND_UNAVAILABLE' -Category CIM -Status Warning -Severity Warning -Message 'Get-CimInstance is unavailable; CIM-backed collectors can complete partially.' -Details ([pscustomobject][ordered]@{
            AffectedCollectors = @($selectedCimCollectors)
        }))
    }

    try {
        $sample = Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $sample) {
            return @(New-ICReadinessCheck -Code 'CIM_QUERY_EMPTY' -Category CIM -Status Warning -Severity Warning -Message 'The CIM readiness query returned no operating-system record.' -Details $null)
        }

        return @(New-ICReadinessCheck -Code 'CIM_QUERY_SUCCEEDED' -Category CIM -Status Passed -Severity Information -Message 'A local CIM query completed successfully.' -Details $null)
    }
    catch {
        return @(New-ICReadinessCheck -Code 'CIM_QUERY_FAILED' -Category CIM -Status Warning -Severity Warning -Message 'The local CIM readiness query failed; CIM-backed collectors can complete partially.' -Details ([pscustomobject][ordered]@{
            Error = $_.Exception.Message
        }))
    }
}

function Test-ICNoMatchingEventsError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    return [string]$ErrorRecord.FullyQualifiedErrorId -like '*NoMatchingEventsFound*'
}

function Test-ICAccessDeniedError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if ($ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or $ErrorRecord.Exception -is [System.Security.SecurityException]) {
        return $true
    }

    $identity = '{0} {1}' -f [string]$ErrorRecord.FullyQualifiedErrorId, [string]$ErrorRecord.Exception.Message
    return $identity -match '(?i)unauthorized|access.?denied|zugriff.?verweigert'
}

function Get-ICEventLogReadinessCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    if ('EventLogs' -notin @($Configuration.Collectors)) {
        return @(New-ICReadinessCheck -Code 'EVENT_LOGS_NOT_SELECTED' -Category EventLogs -Status Passed -Severity Information -Message 'The EventLogs collector is not selected.' -Details $null)
    }

    if ($null -eq (Get-Command -Name 'Get-WinEvent' -ErrorAction SilentlyContinue)) {
        return @(New-ICReadinessCheck -Code 'EVENT_LOG_PROVIDER_UNAVAILABLE' -Category EventLogs -Status Warning -Severity Warning -Message 'Get-WinEvent is unavailable; event channels cannot be inspected or collected.' -Details $null)
    }

    $checks = New-Object System.Collections.ArrayList
    foreach ($logName in @($Configuration.EventLogs)) {
        $optional = $logName -in $script:ICOptionalEventLogs
        try {
            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $logInfo) {
                if ($optional) {
                    [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_OPTIONAL_ABSENT' -Category EventLogs -Status Passed -Severity Information -Message "Optional event channel '$logName' is not present; collection will skip it." -Details ([pscustomobject][ordered]@{ EventLog = $logName; Optional = $true })))
                }
                else {
                    [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_UNAVAILABLE' -Category EventLogs -Status Warning -Severity Warning -Message "Event channel '$logName' was not found." -Details ([pscustomobject][ordered]@{ EventLog = $logName })))
                }
                continue
            }

            $isEnabled = $true
            if ($null -ne $logInfo.PSObject.Properties['IsEnabled']) {
                $isEnabled = [bool]$logInfo.IsEnabled
            }
            if (-not $isEnabled) {
                [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_DISABLED' -Category EventLogs -Status Warning -Severity Warning -Message "Event channel '$logName' exists but is disabled." -Details ([pscustomobject][ordered]@{
                    EventLog = $logName
                    IsEnabled = $false
                })))
                continue
            }

            try {
                $null = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop
                [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_READY' -Category EventLogs -Status Passed -Severity Information -Message "Event channel '$logName' is enabled and readable." -Details ([pscustomobject][ordered]@{
                    EventLog = $logName
                    IsEnabled = $true
                })))
            }
            catch {
                if (Test-ICNoMatchingEventsError -ErrorRecord $_) {
                    [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_READY' -Category EventLogs -Status Passed -Severity Information -Message "Event channel '$logName' is enabled and readable but currently empty." -Details ([pscustomobject][ordered]@{
                        EventLog = $logName
                        IsEnabled = $true
                    })))
                }
                elseif (Test-ICAccessDeniedError -ErrorRecord $_) {
                    [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_ACCESS_DENIED' -Category EventLogs -Status Warning -Severity Warning -Message "Event channel '$logName' exists but cannot be read by the current identity." -Details ([pscustomobject][ordered]@{
                        EventLog = $logName
                        Error = $_.Exception.Message
                    })))
                }
                else {
                    [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_READ_FAILED' -Category EventLogs -Status Warning -Severity Warning -Message "Event channel '$logName' exists but its readability check failed." -Details ([pscustomobject][ordered]@{
                        EventLog = $logName
                        Error = $_.Exception.Message
                    })))
                }
            }
        }
        catch {
            if ($optional -and -not (Test-ICAccessDeniedError -ErrorRecord $_)) {
                [void]$checks.Add((New-ICReadinessCheck -Code 'EVENT_LOG_OPTIONAL_ABSENT' -Category EventLogs -Status Passed -Severity Information -Message "Optional event channel '$logName' is not present; collection will skip it." -Details ([pscustomobject][ordered]@{ EventLog = $logName; Optional = $true })))
                continue
            }
            $code = 'EVENT_LOG_UNAVAILABLE'
            $message = "Event channel '$logName' is unavailable."
            if (Test-ICAccessDeniedError -ErrorRecord $_) {
                $code = 'EVENT_LOG_ACCESS_DENIED'
                $message = "Event channel '$logName' cannot be inspected by the current identity."
            }
            [void]$checks.Add((New-ICReadinessCheck -Code $code -Category EventLogs -Status Warning -Severity Warning -Message $message -Details ([pscustomobject][ordered]@{
                EventLog = $logName
                Error = $_.Exception.Message
            })))
        }
    }

    return @($checks)
}

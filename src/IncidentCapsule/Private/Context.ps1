function Test-ICWindows {
    [CmdletBinding()]
    param()

    if ($env:OS -eq 'Windows_NT') {
        return $true
    }

    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Get-ICCurrentUser {
    [CmdletBinding()]
    param()

    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
            return $env:USERNAME
        }
        return [System.Environment]::UserName
    }
}

function Test-ICAdministrator {
    [CmdletBinding()]
    param()

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-ICHostName {
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        return $env:COMPUTERNAME
    }
    return [System.Environment]::MachineName
}

function New-ICContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$CaseId,

        [Parameter(Mandatory)]
        [string]$Operator,

        [Parameter(Mandatory)]
        [ValidateSet('Minimal', 'Standard', 'Extended')]
        [string]$Profile,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration
    )

    $resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
    if (-not (Test-Path -LiteralPath $resolvedOutput)) {
        New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
    }
    elseif (-not (Test-Path -LiteralPath $resolvedOutput -PathType Container)) {
        throw "OutputPath '$resolvedOutput' is not a directory."
    }

    $start = [datetime]::UtcNow
    $hostName = Get-ICHostName
    $safeCaseId = ConvertTo-ICSafeFileName -Value $CaseId -MaximumLength 50
    $safeHostName = ConvertTo-ICSafeFileName -Value $hostName -MaximumLength 40
    $timestamp = $start.ToString('yyyyMMddTHHmmssZ')
    $random = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $capsuleId = "IC-$timestamp-$random"
    $folderName = "IC_{0}_{1}_{2}_{3}" -f $safeCaseId, $safeHostName, $timestamp, $random
    $root = Join-Path $resolvedOutput $folderName

    if (Test-Path -LiteralPath $root) {
        throw "Capsule root '$root' already exists."
    }

    $directories = [ordered]@{
        Root     = $root
        Evidence = Join-Path $root 'evidence'
        Metadata = Join-Path $root 'metadata'
        Report   = Join-Path $root 'report'
        Logs     = Join-Path $root 'logs'
    }

    foreach ($directory in $directories.Values) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $context = [pscustomobject][ordered]@{
        PSTypeName       = 'IncidentCapsule.Context'
        Name             = $script:ICName
        Version          = $script:ICVersion
        CapsuleId        = $capsuleId
        CaseId           = $CaseId
        Operator         = $Operator
        Profile          = $Profile
        HostName         = $hostName
        IsElevated       = Test-ICAdministrator
        StartedAtUtc     = $start
        CompletedAtUtc   = $null
        Status           = 'Running'
        CollectionStatus = 'Running'
        FinalizationStatus = 'NotStarted'
        OutputPath       = $resolvedOutput
        RootPath         = $root
        EvidencePath     = $directories.Evidence
        MetadataPath     = $directories.Metadata
        ReportDirectory  = $directories.Report
        LogDirectory     = $directories.Logs
        LogPath          = Join-Path $directories.Logs 'collector.log'
        ReportPath       = Join-Path $directories.Report 'index.html'
        ManifestPath     = Join-Path $directories.Metadata 'manifest.json'
        ManifestTextPath = Join-Path $directories.Metadata 'manifest.sha256'
        ArchivePath      = $null
        ArchiveHashPath  = $null
        Configuration    = $Configuration
        CollectorResults = New-Object System.Collections.ArrayList
        FatalError       = $null
        Frozen           = $false
    }

    return $context
}

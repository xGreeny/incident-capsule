function Get-ICPowerShellEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $engineCommands = New-Object System.Collections.ArrayList
    foreach ($name in @('powershell.exe', 'pwsh.exe')) {
        foreach ($command in @(Get-Command -Name $name -CommandType Application -All -ErrorAction SilentlyContinue)) {
            [void]$engineCommands.Add([pscustomobject][ordered]@{
                Name = $command.Name
                Source = $command.Source
                Version = if ($null -ne $command.Version) { $command.Version.ToString() } else { $null }
                FileVersion = try { (Get-Item -LiteralPath $command.Source -ErrorAction Stop).VersionInfo.FileVersion } catch { $null }
            })
        }
    }

    $engineRegistry = @(Get-ICRegistryValues -Path @(
        'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine',
        'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\PowerShell\1\PowerShellEngine',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\PowerShell\3\PowerShellEngine'
    ))

    $currentEngine = [ordered]@{
        PSVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' }
        GitCommitId = if ($PSVersionTable.ContainsKey('GitCommitId')) { $PSVersionTable.GitCommitId } else { $null }
        OS = if ($PSVersionTable.ContainsKey('OS')) { $PSVersionTable.OS } else { [System.Environment]::OSVersion.VersionString }
        Platform = if ($PSVersionTable.ContainsKey('Platform')) { $PSVersionTable.Platform } else { 'Win32NT' }
        CLRVersion = if ($PSVersionTable.ContainsKey('CLRVersion')) { [string]$PSVersionTable.CLRVersion } else { $null }
        WSManStackVersion = if ($PSVersionTable.ContainsKey('WSManStackVersion')) { [string]$PSVersionTable.WSManStackVersion } else { $null }
        SerializationVersion = if ($PSVersionTable.ContainsKey('SerializationVersion')) { [string]$PSVersionTable.SerializationVersion } else { $null }
    }

    $enginesData = [ordered]@{
        CurrentProcess = $currentEngine
        Commands = @($engineCommands)
        Registry = $engineRegistry
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector PowerShell -RelativePath 'evidence/powershell/engines.json' -Data $enginesData)

    $executionPolicies = @()
    try {
        $executionPolicies = @(Get-ExecutionPolicy -List -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Scope = $_.Scope.ToString()
                ExecutionPolicy = $_.ExecutionPolicy.ToString()
            }
        })
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Execution policy: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector PowerShell -RelativePath 'evidence/powershell/execution-policy.json' -Data $executionPolicies -Csv)

    $loggingPolicy = @(Get-ICRegistryValues -Path @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    ))
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector PowerShell -RelativePath 'evidence/powershell/logging-policy.json' -Data $loggingPolicy -Csv)

    $modules = @()
    try {
        $modules = @(Get-Module -ListAvailable -ErrorAction Stop |
            Sort-Object Name, Version, Path -Unique |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    Version = $_.Version.ToString()
                    ModuleType = $_.ModuleType.ToString()
                    Path = $_.Path
                    RootModule = $_.RootModule
                    Author = $_.Author
                    CompanyName = $_.CompanyName
                    PowerShellVersion = [string]$_.PowerShellVersion
                    CompatiblePSEditions = @($_.CompatiblePSEditions)
                    Guid = [string]$_.Guid
                }
            })
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "PowerShell module inventory: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector PowerShell -RelativePath 'evidence/powershell/modules.json' -Data $modules -Csv)

    $profilePaths = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $profileVariable = Get-Variable -Name PROFILE -Scope Global -ErrorAction Stop
        foreach ($propertyName in @('AllUsersAllHosts', 'AllUsersCurrentHost', 'CurrentUserAllHosts', 'CurrentUserCurrentHost')) {
            $path = Get-ICPropertyValue -InputObject $profileVariable.Value -Name $propertyName
            if (-not [string]::IsNullOrWhiteSpace([string]$path)) { [void]$profilePaths.Add([string]$path) }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$profileVariable.Value)) { [void]$profilePaths.Add([string]$profileVariable.Value) }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "PowerShell profile paths: $($_.Exception.Message)" }

    $historyPath = $null
    if (Test-ICCommandAvailable -Name 'Get-PSReadLineOption') {
        try { $historyPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath } catch { }
    }

    $profileMetadata = New-Object System.Collections.ArrayList
    foreach ($path in $profilePaths) {
        [void]$profileMetadata.Add((Get-ICFileMetadata -Path $path -Hash))
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$historyPath)) {
        $historyMetadata = Get-ICFileMetadata -Path $historyPath -Hash
        $historyMetadata | Add-Member -NotePropertyName ContentCollected -NotePropertyValue $false -Force
        $historyMetadata | Add-Member -NotePropertyName Type -NotePropertyValue 'PSReadLineHistoryMetadataOnly' -Force
        [void]$profileMetadata.Add($historyMetadata)
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector PowerShell -RelativePath 'evidence/powershell/profiles.json' -Data @($profileMetadata) -Csv)

    $scriptBlockLogging = @($loggingPolicy | Where-Object ValueName -eq 'EnableScriptBlockLogging' | Where-Object Data -eq 1).Count -gt 0
    $moduleLogging = @($loggingPolicy | Where-Object ValueName -eq 'EnableModuleLogging' | Where-Object Data -eq 1).Count -gt 0
    $transcription = @($loggingPolicy | Where-Object ValueName -eq 'EnableTranscripting' | Where-Object Data -eq 1).Count -gt 0

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        CurrentPowerShellVersion = $PSVersionTable.PSVersion.ToString()
        DiscoveredEngineCommands = $engineCommands.Count
        AvailableModules = $modules.Count
        ScriptBlockLoggingPolicyEnabled = $scriptBlockLogging
        ModuleLoggingPolicyEnabled = $moduleLogging
        TranscriptionPolicyEnabled = $transcription
        HistoryContentCollected = $false
    })
}

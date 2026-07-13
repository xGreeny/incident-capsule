function Get-ICPersistenceEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $runKeys = New-Object System.Collections.Generic.List[string]
    foreach ($path in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )) {
        $runKeys.Add($path)
    }

    try {
        foreach ($hive in Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop) {
            $sidName = Split-Path -Leaf $hive.Name
            if ($sidName -match '_Classes$') {
                continue
            }
            $runKeys.Add("Registry::HKEY_USERS\$sidName\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
            $runKeys.Add("Registry::HKEY_USERS\$sidName\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            $runKeys.Add("Registry::HKEY_USERS\$sidName\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Loaded user registry hives: $($_.Exception.Message)" }

    $registryAutoruns = @()
    try {
        $registryAutoruns += @(Get-ICRegistryValues -Path @($runKeys))
        $registryAutoruns += @(Get-ICRegistryValues -Path @(
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
            'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        ) -ValueName @('Shell', 'Userinit', 'Taskman', 'VmApplet', 'Load', 'Run'))
        $registryAutoruns += @(Get-ICRegistryValues -Path @(
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
        ) -ValueName @('AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs'))
        $registryAutoruns += @(Get-ICRegistryValues -Path @(
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        ) -ValueName @('Authentication Packages', 'Notification Packages', 'Security Packages'))
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Autorun registry snapshot: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Persistence -RelativePath 'evidence/persistence/registry-autoruns.json' -Data $registryAutoruns -Csv)

    $ifeo = New-Object System.Collections.ArrayList
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        try {
            foreach ($subKey in Get-ChildItem -LiteralPath $root -ErrorAction Stop) {
                $values = Get-ICRegistryValues -Path @($subKey.PSPath) -ValueName @('Debugger', 'GlobalFlag', 'VerifierDlls')
                foreach ($value in $values) {
                    if ($null -ne $value.Data -and -not [string]::IsNullOrWhiteSpace([string]$value.Data)) {
                        [void]$ifeo.Add($value)
                    }
                }
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "IFEO snapshot '$root': $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Persistence -RelativePath 'evidence/persistence/ifeo-debuggers.json' -Data @($ifeo) -Csv)

    $startupDirectories = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($folderName in @('Startup', 'CommonStartup')) {
        try {
            $folder = [System.Environment]::GetFolderPath($folderName)
            if (-not [string]::IsNullOrWhiteSpace($folder)) { [void]$startupDirectories.Add($folder) }
        }
        catch { }
    }
    try {
        foreach ($profile in Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop) {
            if (-not [string]::IsNullOrWhiteSpace([string]$profile.LocalPath)) {
                [void]$startupDirectories.Add((Join-Path $profile.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
            }
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "User profile startup paths: $($_.Exception.Message)" }

    $startupFiles = New-Object System.Collections.ArrayList
    foreach ($directory in $startupDirectories) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            continue
        }
        try {
            foreach ($item in Get-ChildItem -LiteralPath $directory -File -Recurse -Force -ErrorAction Stop) {
                $metadata = Get-ICFileMetadata -Path $item.FullName -Hash:$Context.Configuration.HashPersistenceFiles
                $metadata | Add-Member -NotePropertyName StartupDirectory -NotePropertyValue $directory -Force
                [void]$startupFiles.Add($metadata)
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Startup folder '$directory': $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Persistence -RelativePath 'evidence/persistence/startup-files.json' -Data @($startupFiles) -Csv)

    $wmiSubscriptions = New-Object System.Collections.ArrayList
    if ($Context.Configuration.CollectWmiSubscriptions) {
        $classes = @(
            '__EventFilter',
            'CommandLineEventConsumer',
            'ActiveScriptEventConsumer',
            'LogFileEventConsumer',
            'NTEventLogEventConsumer',
            'SMTPEventConsumer',
            '__FilterToConsumerBinding'
        )
        foreach ($className in $classes) {
            try {
                foreach ($instance in Get-CimInstance -Namespace 'root/subscription' -ClassName $className -ErrorAction Stop) {
                    [void]$wmiSubscriptions.Add([pscustomobject][ordered]@{
                        Class = $className
                        RelativePath = Get-ICPropertyValue -InputObject $instance.CimSystemProperties -Name 'Path'
                        Name = Get-ICPropertyValue -InputObject $instance -Name 'Name'
                        Query = Get-ICPropertyValue -InputObject $instance -Name 'Query'
                        QueryLanguage = Get-ICPropertyValue -InputObject $instance -Name 'QueryLanguage'
                        EventNamespace = Get-ICPropertyValue -InputObject $instance -Name 'EventNamespace'
                        CommandLineTemplate = Get-ICPropertyValue -InputObject $instance -Name 'CommandLineTemplate'
                        ExecutablePath = Get-ICPropertyValue -InputObject $instance -Name 'ExecutablePath'
                        ScriptingEngine = Get-ICPropertyValue -InputObject $instance -Name 'ScriptingEngine'
                        ScriptText = Get-ICPropertyValue -InputObject $instance -Name 'ScriptText'
                        Filter = [string](Get-ICPropertyValue -InputObject $instance -Name 'Filter')
                        Consumer = [string](Get-ICPropertyValue -InputObject $instance -Name 'Consumer')
                    })
                }
            }
            catch { Add-ICCollectorWarning -List $warnings -Message "WMI subscription class '$className': $($_.Exception.Message)" }
        }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Persistence -RelativePath 'evidence/persistence/wmi-subscriptions.json' -Data @($wmiSubscriptions))

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        RegistryAutorunValues = $registryAutoruns.Count
        IfeoDebuggerValues = $ifeo.Count
        StartupFiles = $startupFiles.Count
        WmiSubscriptionObjects = $wmiSubscriptions.Count
        PersistenceFilesHashed = [bool]$Context.Configuration.HashPersistenceFiles
    })
}

function Get-ICInstalledSoftwareEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    # Win32_Product is intentionally not queried: enumerating it triggers MSI
    # consistency checks that can reconfigure installed products on the host.
    $roots = New-Object System.Collections.ArrayList
    [void]$roots.Add([pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine' })
    [void]$roots.Add([pscustomobject]@{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine32' })
    try {
        foreach ($hive in Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop) {
            $sidName = Split-Path -Leaf $hive.Name
            if ($sidName -match '_Classes$') {
                continue
            }
            [void]$roots.Add([pscustomobject]@{
                Path  = "Registry::HKEY_USERS\$sidName\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
                Scope = "User:$sidName"
            })
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Loaded user registry hives: $($_.Exception.Message)" }

    $entries = New-Object System.Collections.ArrayList
    $machineEntries = 0
    $userEntries = 0
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root.Path)) {
            continue
        }
        try {
            foreach ($key in Get-ChildItem -LiteralPath $root.Path -ErrorAction Stop) {
                try {
                    $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                    $estimatedSize = Get-ICPropertyValue -InputObject $properties -Name 'EstimatedSize'
                    [void]$entries.Add([pscustomobject][ordered]@{
                        Scope                = [string]$root.Scope
                        KeyName              = Split-Path -Leaf $key.Name
                        DisplayName          = [string](Get-ICPropertyValue -InputObject $properties -Name 'DisplayName')
                        DisplayVersion       = [string](Get-ICPropertyValue -InputObject $properties -Name 'DisplayVersion')
                        Publisher            = [string](Get-ICPropertyValue -InputObject $properties -Name 'Publisher')
                        InstallDate          = [string](Get-ICPropertyValue -InputObject $properties -Name 'InstallDate')
                        InstallLocation      = [string](Get-ICPropertyValue -InputObject $properties -Name 'InstallLocation')
                        InstallSource        = [string](Get-ICPropertyValue -InputObject $properties -Name 'InstallSource')
                        UninstallString      = [string](Get-ICPropertyValue -InputObject $properties -Name 'UninstallString')
                        QuietUninstallString = [string](Get-ICPropertyValue -InputObject $properties -Name 'QuietUninstallString')
                        EstimatedSizeKB      = if ($null -ne $estimatedSize) { [int64]$estimatedSize } else { $null }
                        SystemComponent      = [bool]([int](Get-ICPropertyValue -InputObject $properties -Name 'SystemComponent' -Default 0) -eq 1)
                        WindowsInstaller     = [bool]([int](Get-ICPropertyValue -InputObject $properties -Name 'WindowsInstaller' -Default 0) -eq 1)
                        RegistryKey          = [string]$key.Name
                    })
                    if ($root.Scope -like 'User:*') { $userEntries++ } else { $machineEntries++ }
                }
                catch { Add-ICCollectorWarning -List $warnings -Message "Uninstall entry '$($key.Name)': $($_.Exception.Message)" }
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Uninstall inventory '$($root.Path)': $($_.Exception.Message)" }
    }

    $sorted = @($entries | Sort-Object Scope, DisplayName, KeyName)
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector InstalledSoftware -RelativePath 'evidence/software/installed-software.json' -Data $sorted -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        InstalledSoftwareEntries = $sorted.Count
        MachineScopeEntries      = $machineEntries
        UserScopeEntries         = $userEntries
    })
}

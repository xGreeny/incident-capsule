function Get-ICSystemEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $os = $null
    $computer = $null
    $bios = $null
    $product = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { Add-ICCollectorWarning -List $warnings -Message "Win32_OperatingSystem: $($_.Exception.Message)" }
    try { $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { Add-ICCollectorWarning -List $warnings -Message "Win32_ComputerSystem: $($_.Exception.Message)" }
    try { $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop } catch { Add-ICCollectorWarning -List $warnings -Message "Win32_BIOS: $($_.Exception.Message)" }
    try { $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop } catch { Add-ICCollectorWarning -List $warnings -Message "Win32_ComputerSystemProduct: $($_.Exception.Message)" }

    $secureBoot = $null
    if (Test-ICCommandAvailable -Name 'Confirm-SecureBootUEFI') {
        try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { Add-ICCollectorWarning -List $warnings -Message "Secure Boot state: $($_.Exception.Message)" }
    }

    $tpm = $null
    if (Test-ICCommandAvailable -Name 'Get-Tpm') {
        try {
            $tpmSource = Get-Tpm -ErrorAction Stop
            $tpm = [ordered]@{
                TpmPresent            = Get-ICPropertyValue -InputObject $tpmSource -Name 'TpmPresent'
                TpmReady              = Get-ICPropertyValue -InputObject $tpmSource -Name 'TpmReady'
                TpmEnabled            = Get-ICPropertyValue -InputObject $tpmSource -Name 'TpmEnabled'
                TpmActivated          = Get-ICPropertyValue -InputObject $tpmSource -Name 'TpmActivated'
                TpmOwned              = Get-ICPropertyValue -InputObject $tpmSource -Name 'TpmOwned'
                RestartPending        = Get-ICPropertyValue -InputObject $tpmSource -Name 'RestartPending'
                ManufacturerIdTxt     = Get-ICPropertyValue -InputObject $tpmSource -Name 'ManufacturerIdTxt'
                ManufacturerVersion   = Get-ICPropertyValue -InputObject $tpmSource -Name 'ManufacturerVersion'
                AutoProvisioning      = Get-ICPropertyValue -InputObject $tpmSource -Name 'AutoProvisioning'
                LockedOut             = Get-ICPropertyValue -InputObject $tpmSource -Name 'LockedOut'
                LockoutCount          = Get-ICPropertyValue -InputObject $tpmSource -Name 'LockoutCount'
                LockoutMax            = Get-ICPropertyValue -InputObject $tpmSource -Name 'LockoutMax'
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "TPM state: $($_.Exception.Message)" }
    }

    $currentVersion = Get-ICRegistryValues -Path @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') -ValueName @(
        'ProductName', 'DisplayVersion', 'EditionID', 'InstallationType', 'CurrentBuild',
        'CurrentBuildNumber', 'UBR', 'BuildLabEx', 'InstallDate', 'RegisteredOwner'
    )

    $systemData = [ordered]@{
        HostName = $Context.HostName
        Domain = Get-ICPropertyValue -InputObject $computer -Name 'Domain'
        DomainRole = Get-ICPropertyValue -InputObject $computer -Name 'DomainRole'
        PartOfDomain = Get-ICPropertyValue -InputObject $computer -Name 'PartOfDomain'
        Manufacturer = Get-ICPropertyValue -InputObject $computer -Name 'Manufacturer'
        Model = Get-ICPropertyValue -InputObject $computer -Name 'Model'
        SystemType = Get-ICPropertyValue -InputObject $computer -Name 'SystemType'
        TotalPhysicalMemory = Get-ICPropertyValue -InputObject $computer -Name 'TotalPhysicalMemory'
        LoggedOnUser = Get-ICPropertyValue -InputObject $computer -Name 'UserName'
        OperatingSystem = [ordered]@{
            Caption = Get-ICPropertyValue -InputObject $os -Name 'Caption'
            Version = Get-ICPropertyValue -InputObject $os -Name 'Version'
            BuildNumber = Get-ICPropertyValue -InputObject $os -Name 'BuildNumber'
            OSArchitecture = Get-ICPropertyValue -InputObject $os -Name 'OSArchitecture'
            Locale = Get-ICPropertyValue -InputObject $os -Name 'Locale'
            MUILanguages = Get-ICPropertyValue -InputObject $os -Name 'MUILanguages'
            InstallDate = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $os -Name 'InstallDate')
            LastBootUpTime = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $os -Name 'LastBootUpTime')
            FreePhysicalMemoryKB = Get-ICPropertyValue -InputObject $os -Name 'FreePhysicalMemory'
            CurrentVersionRegistry = $currentVersion
        }
        BIOS = [ordered]@{
            Manufacturer = Get-ICPropertyValue -InputObject $bios -Name 'Manufacturer'
            Name = Get-ICPropertyValue -InputObject $bios -Name 'Name'
            SMBIOSBIOSVersion = Get-ICPropertyValue -InputObject $bios -Name 'SMBIOSBIOSVersion'
            SerialNumber = Get-ICPropertyValue -InputObject $bios -Name 'SerialNumber'
            ReleaseDate = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $bios -Name 'ReleaseDate')
        }
        Product = [ordered]@{
            Vendor = Get-ICPropertyValue -InputObject $product -Name 'Vendor'
            Name = Get-ICPropertyValue -InputObject $product -Name 'Name'
            Version = Get-ICPropertyValue -InputObject $product -Name 'Version'
            UUID = Get-ICPropertyValue -InputObject $product -Name 'UUID'
            IdentifyingNumber = Get-ICPropertyValue -InputObject $product -Name 'IdentifyingNumber'
        }
        SecurityHardware = [ordered]@{
            SecureBootEnabled = $secureBoot
            TPM = $tpm
        }
        Execution = [ordered]@{
            User = Get-ICCurrentUser
            Elevated = [bool]$Context.IsElevated
            ProcessId = $PID
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PowerShellEdition = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' }
            ProcessArchitecture = if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        }
    }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector System -RelativePath 'evidence/system/system.json' -Data $systemData)

    $timeZone = $null
    if (Test-ICCommandAvailable -Name 'Get-TimeZone') {
        try {
            $zone = Get-TimeZone -ErrorAction Stop
            $timeZone = [ordered]@{
                Id = $zone.Id
                DisplayName = $zone.DisplayName
                StandardName = $zone.StandardName
                DaylightName = $zone.DaylightName
                BaseUtcOffset = $zone.BaseUtcOffset.ToString()
                SupportsDaylightSavingTime = $zone.SupportsDaylightSavingTime
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Time zone: $($_.Exception.Message)" }
    }

    $w32Time = $null
    try {
        $service = Get-Service -Name W32Time -ErrorAction Stop
        $w32Time = [ordered]@{
            Status = $service.Status.ToString()
            StartType = Get-ICPropertyValue -InputObject $service -Name 'StartType'
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Windows Time service: $($_.Exception.Message)" }

    $timeData = [ordered]@{
        CapturedAtUtc = [datetime]::UtcNow.ToString('o')
        LocalTime = (Get-Date).ToString('o')
        TickCount64 = [System.Environment]::TickCount64
        TimeZone = $timeZone
        WindowsTimeService = $w32Time
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector System -RelativePath 'evidence/system/time.json' -Data $timeData)

    $whoamiResult = Export-ICNativeCommandOutput -Context $Context -RelativePath 'evidence/system/whoami.txt' -FilePath (Get-ICSystemExecutable -Name 'whoami.exe') -ArgumentList @('/all')
    [void]$files.Add($whoamiResult.Path)
    if ($null -ne $whoamiResult.Error -or ($null -ne $whoamiResult.ExitCode -and $whoamiResult.ExitCode -ne 0)) {
        Add-ICCollectorWarning -List $warnings -Message "whoami /all failed: $($whoamiResult.Error)"
    }

    $w32tmResult = Export-ICNativeCommandOutput -Context $Context -RelativePath 'evidence/system/w32tm-status.txt' -FilePath (Get-ICSystemExecutable -Name 'w32tm.exe') -ArgumentList @('/query', '/status')
    [void]$files.Add($w32tmResult.Path)
    if ($null -ne $w32tmResult.Error -or ($null -ne $w32tmResult.ExitCode -and $w32tmResult.ExitCode -ne 0)) {
        Add-ICCollectorWarning -List $warnings -Message 'w32tm status was unavailable; inspect the native output file.'
    }

    $uptimeHours = $null
    if ($null -ne $os) {
        try { $uptimeHours = [math]::Round(([datetime]::UtcNow - ([datetime]$os.LastBootUpTime).ToUniversalTime()).TotalHours, 2) } catch { }
    }

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        UptimeHours = $uptimeHours
        Elevated = [bool]$Context.IsElevated
        SecureBootEnabled = $secureBoot
        TpmPresent = if ($null -ne $tpm) { $tpm.TpmPresent } else { $null }
    })
}

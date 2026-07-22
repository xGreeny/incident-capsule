function ConvertTo-ICMountedDeviceValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Data
    )

    if ($Data -isnot [byte[]] -or $Data.Length -eq 0) {
        return [pscustomobject]@{ Decoded = $null; HexPrefix = $null }
    }

    $bytes = [byte[]]$Data
    $decoded = $null
    if (($bytes.Length % 2) -eq 0) {
        try {
            $candidate = [System.Text.Encoding]::Unicode.GetString($bytes)
            if ($candidate -match '^[\x20-\x7E]+$') {
                $decoded = $candidate
            }
        }
        catch { $decoded = $null }
    }

    $prefixLength = [math]::Min($bytes.Length, 64)
    $hexPrefix = -join (@($bytes[0..($prefixLength - 1)]) | ForEach-Object { $_.ToString('x2') })
    return [pscustomobject]@{ Decoded = $decoded; HexPrefix = $hexPrefix }
}

function Get-ICDeviceEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $maximumArtifactBytes = [int64](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'MaximumArtifactFileBytes' -Default 33554432L)

    $usbDevices = New-Object System.Collections.ArrayList
    $usbRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (Test-Path -LiteralPath $usbRoot) {
        try {
            foreach ($deviceClassKey in Get-ChildItem -LiteralPath $usbRoot -ErrorAction Stop) {
                foreach ($instanceKey in Get-ChildItem -LiteralPath $deviceClassKey.PSPath -ErrorAction SilentlyContinue) {
                    try {
                        $properties = Get-ItemProperty -LiteralPath $instanceKey.PSPath -ErrorAction Stop
                        $hardwareId = @(Get-ICPropertyValue -InputObject $properties -Name 'HardwareID' -Default @())
                        [void]$usbDevices.Add([pscustomobject][ordered]@{
                            DeviceClass  = Split-Path -Leaf $deviceClassKey.Name
                            SerialNumber = Split-Path -Leaf $instanceKey.Name
                            FriendlyName = [string](Get-ICPropertyValue -InputObject $properties -Name 'FriendlyName')
                            DeviceDesc   = [string](Get-ICPropertyValue -InputObject $properties -Name 'DeviceDesc')
                            Manufacturer = [string](Get-ICPropertyValue -InputObject $properties -Name 'Mfg')
                            Service      = [string](Get-ICPropertyValue -InputObject $properties -Name 'Service')
                            ContainerID  = [string](Get-ICPropertyValue -InputObject $properties -Name 'ContainerID')
                            HardwareID   = (@($hardwareId) -join '; ')
                            RegistryKey  = [string]$instanceKey.Name
                        })
                    }
                    catch { Add-ICCollectorWarning -List $warnings -Message "USBSTOR instance '$($instanceKey.Name)': $($_.Exception.Message)" }
                }
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "USBSTOR enumeration: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Devices -RelativePath 'evidence/devices/usb-storage.json' -Data @($usbDevices | Sort-Object DeviceClass, SerialNumber) -Csv)

    $mountedDevices = New-Object System.Collections.ArrayList
    try {
        $properties = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\MountedDevices' -ErrorAction Stop
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                continue
            }
            $value = ConvertTo-ICMountedDeviceValue -Data $property.Value
            [void]$mountedDevices.Add([pscustomobject][ordered]@{
                Name        = [string]$property.Name
                Decoded     = $value.Decoded
                HexPrefix   = $value.HexPrefix
                LengthBytes = if ($property.Value -is [byte[]]) { ([byte[]]$property.Value).Length } else { $null }
            })
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "MountedDevices snapshot: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Devices -RelativePath 'evidence/devices/mounted-devices.json' -Data @($mountedDevices | Sort-Object Name) -Csv)

    $mountPoints = New-Object System.Collections.ArrayList
    try {
        foreach ($hive in Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop) {
            $sidName = Split-Path -Leaf $hive.Name
            if ($sidName -match '_Classes$') {
                continue
            }
            $mountPointRoot = "Registry::HKEY_USERS\$sidName\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
            if (-not (Test-Path -LiteralPath $mountPointRoot)) {
                continue
            }
            try {
                foreach ($mountKey in Get-ChildItem -LiteralPath $mountPointRoot -ErrorAction Stop) {
                    [void]$mountPoints.Add([pscustomobject][ordered]@{
                        Sid        = $sidName
                        MountPoint = Split-Path -Leaf $mountKey.Name
                    })
                }
            }
            catch { Add-ICCollectorWarning -List $warnings -Message "MountPoints2 hive '$sidName': $($_.Exception.Message)" }
        }
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "MountPoints2 enumeration: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Devices -RelativePath 'evidence/devices/mountpoints.json' -Data @($mountPoints | Sort-Object Sid, MountPoint) -Csv)

    $portableDevices = New-Object System.Collections.ArrayList
    $portableRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
    if (Test-Path -LiteralPath $portableRoot) {
        try {
            foreach ($deviceKey in Get-ChildItem -LiteralPath $portableRoot -ErrorAction Stop) {
                $friendlyName = $null
                try {
                    $properties = Get-ItemProperty -LiteralPath $deviceKey.PSPath -ErrorAction Stop
                    $friendlyName = [string](Get-ICPropertyValue -InputObject $properties -Name 'FriendlyName')
                }
                catch { $friendlyName = $null }
                [void]$portableDevices.Add([pscustomobject][ordered]@{
                    DeviceKey    = Split-Path -Leaf $deviceKey.Name
                    FriendlyName = $friendlyName
                })
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Windows Portable Devices enumeration: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Devices -RelativePath 'evidence/devices/portable-devices.json' -Data @($portableDevices | Sort-Object DeviceKey) -Csv)

    $setupApiCopied = $false
    $setupApiPath = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
    $setupApiRecord = Get-ICFileMetadata -Path $setupApiPath
    if ((Get-ICPropertyValue -InputObject $setupApiRecord -Name 'Error')) {
        Add-ICCollectorWarning -List $warnings -Message "Device setup log '$setupApiPath' is unavailable."
    }
    elseif ([int64]$setupApiRecord.Length -gt $maximumArtifactBytes) {
        Add-ICCollectorWarning -List $warnings -Message ("Device setup log copy bounded: '{0}' ({1} bytes) exceeds MaximumArtifactFileBytes={2}; metadata was recorded without the file content." -f $setupApiPath, $setupApiRecord.Length, $maximumArtifactBytes)
    }
    else {
        try {
            $destinationPath = Join-Path $Context.RootPath 'evidence\devices\setupapi.dev.log'
            [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $destinationPath))
            [System.IO.File]::Copy($setupApiPath, $destinationPath, $false)
            Add-ICOutputFiles -List $files -Path @($destinationPath)
            $setupApiCopied = $true
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Device setup log copy: $($_.Exception.Message)" }
    }
    $setupApiRecord | Add-Member -NotePropertyName Copied -NotePropertyValue $setupApiCopied -Force
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Devices -RelativePath 'evidence/devices/setupapi-log.json' -Data $setupApiRecord)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        UsbStorageDevices   = $usbDevices.Count
        MountedDeviceValues = $mountedDevices.Count
        UserMountPoints     = $mountPoints.Count
        PortableDevices     = $portableDevices.Count
        SetupApiLogCopied   = $setupApiCopied
    })
}

function Get-ICStorageEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $disks = @()
    try {
        $disks = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Index = $_.Index
                DeviceID = $_.DeviceID
                Model = $_.Model
                Manufacturer = $_.Manufacturer
                SerialNumber = if ($null -ne $_.SerialNumber) { $_.SerialNumber.Trim() } else { $null }
                InterfaceType = $_.InterfaceType
                MediaType = $_.MediaType
                FirmwareRevision = $_.FirmwareRevision
                Size = [int64]$_.Size
                Partitions = $_.Partitions
                Status = $_.Status
            }
        })
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Disk inventory: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Storage -RelativePath 'evidence/storage/disks.json' -Data $disks -Csv)

    $volumes = @()
    if (Test-ICCommandAvailable -Name 'Get-Volume') {
        try {
            $volumes = @(Get-Volume -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    DriveLetter = $_.DriveLetter
                    FileSystemLabel = $_.FileSystemLabel
                    FileSystem = $_.FileSystem
                    DriveType = $_.DriveType.ToString()
                    HealthStatus = $_.HealthStatus.ToString()
                    OperationalStatus = ($_.OperationalStatus -join ',')
                    Size = $_.Size
                    SizeRemaining = $_.SizeRemaining
                    Path = $_.Path
                    UniqueId = $_.UniqueId
                    AllocationUnitSize = $_.AllocationUnitSize
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Volume inventory: $($_.Exception.Message)" }
    }
    else {
        try {
            $volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    DriveLetter = $_.DeviceID
                    FileSystemLabel = $_.VolumeName
                    FileSystem = $_.FileSystem
                    DriveType = $_.DriveType
                    Size = $_.Size
                    SizeRemaining = $_.FreeSpace
                    VolumeSerialNumber = $_.VolumeSerialNumber
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Logical disk inventory: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Storage -RelativePath 'evidence/storage/volumes.json' -Data $volumes -Csv)

    $shares = @()
    if (Test-ICCommandAvailable -Name 'Get-SmbShare') {
        try {
            $shares = @(Get-SmbShare -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    ScopeName = $_.ScopeName
                    Path = $_.Path
                    Description = $_.Description
                    Special = $_.Special
                    Temporary = $_.Temporary
                    EncryptData = $_.EncryptData
                    FolderEnumerationMode = $_.FolderEnumerationMode.ToString()
                    CachingMode = $_.CachingMode.ToString()
                    ContinuouslyAvailable = $_.ContinuouslyAvailable
                    ConcurrentUserLimit = $_.ConcurrentUserLimit
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "SMB share inventory: $($_.Exception.Message)" }
    }
    else {
        try {
            $shares = @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | Select-Object Name, Path, Description, Type, Status)
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Share inventory: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Storage -RelativePath 'evidence/storage/shares.json' -Data $shares -Csv)

    $bitLocker = @()
    if (Test-ICCommandAvailable -Name 'Get-BitLockerVolume') {
        try {
            $bitLocker = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    MountPoint = $_.MountPoint
                    VolumeType = $_.VolumeType.ToString()
                    VolumeStatus = $_.VolumeStatus.ToString()
                    ProtectionStatus = $_.ProtectionStatus.ToString()
                    EncryptionPercentage = $_.EncryptionPercentage
                    EncryptionMethod = $_.EncryptionMethod.ToString()
                    AutoUnlockEnabled = $_.AutoUnlockEnabled
                    AutoUnlockKeyStored = $_.AutoUnlockKeyStored
                    LockStatus = $_.LockStatus.ToString()
                    KeyProtectorTypes = @($_.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "BitLocker status: $($_.Exception.Message)" }
    }
    else {
        Add-ICCollectorWarning -List $warnings -Message 'Get-BitLockerVolume is unavailable; BitLocker status was not collected.'
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Storage -RelativePath 'evidence/storage/bitlocker.json' -Data $bitLocker)

    $totalBytes = [double](($volumes | Measure-Object -Property Size -Sum).Sum)
    $freeBytes = [double](($volumes | Measure-Object -Property SizeRemaining -Sum).Sum)
    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        PhysicalDisks = $disks.Count
        Volumes = $volumes.Count
        Shares = $shares.Count
        TotalBytes = $totalBytes
        FreeBytes = $freeBytes
        BitLockerVolumes = $bitLocker.Count
    })
}

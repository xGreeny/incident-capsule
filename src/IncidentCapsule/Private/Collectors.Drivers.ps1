function Get-ICDriverEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $systemDrivers = @()
    $signedDrivers = @()

    try {
        $systemDrivers = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Description = $_.Description
                State = $_.State
                Status = $_.Status
                Started = $_.Started
                StartMode = $_.StartMode
                ServiceType = $_.ServiceType
                PathName = $_.PathName
                ErrorControl = $_.ErrorControl
                ExitCode = $_.ExitCode
                TagId = $_.TagId
                AcceptPause = $_.AcceptPause
                AcceptStop = $_.AcceptStop
            }
        } | Sort-Object Name)
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "System driver inventory: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Drivers -RelativePath 'evidence/drivers/system-drivers.json' -Data $systemDrivers -Csv)

    if ($Context.Configuration.CollectSignedDrivers) {
        try {
            $maximumSignedDrivers = [int]$Context.Configuration.MaximumSignedDrivers
            $boundedSignedDrivers = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop | Select-Object -First ($maximumSignedDrivers + 1))
            $signedDrivers = @($boundedSignedDrivers | Select-Object -First $maximumSignedDrivers | ForEach-Object {
                [pscustomobject][ordered]@{
                    DeviceName = $_.DeviceName
                    DeviceID = $_.DeviceID
                    DriverVersion = $_.DriverVersion
                    DriverDateUtc = ConvertTo-ICIso8601 -Value $_.DriverDate
                    DriverProviderName = $_.DriverProviderName
                    Manufacturer = $_.Manufacturer
                    InfName = $_.InfName
                    IsSigned = $_.IsSigned
                    Signer = $_.Signer
                    Started = $_.Started
                    Status = $_.Status
                    ClassGuid = $_.ClassGuid
                    FriendlyName = $_.FriendlyName
                    HardWareID = $_.HardWareID
                }
            })
            if ($boundedSignedDrivers.Count -gt $signedDrivers.Count) {
                Add-ICCollectorWarning -List $warnings -Message "Signed-driver export reached the configured limit of $($signedDrivers.Count) entries; additional entries exist."
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Signed PnP drivers: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Drivers -RelativePath 'evidence/drivers/signed-pnp-drivers.json' -Data $signedDrivers -Csv)

    $driverQuery = Invoke-ICNativeCommand -FilePath (Get-ICSystemExecutable -Name 'driverquery.exe') -ArgumentList @('/v', '/fo', 'csv') -Context $Context
    $driverQueryPath = Join-Path $Context.RootPath 'evidence/drivers/driverquery.csv'
    [void](Write-ICUtf8File -Path $driverQueryPath -Content ((@($driverQuery.Output) -join [Environment]::NewLine) + [Environment]::NewLine))
    [void]$files.Add($driverQueryPath)
    if ($null -ne $driverQuery.Error -or ($null -ne $driverQuery.ExitCode -and $driverQuery.ExitCode -ne 0)) {
        Add-ICCollectorWarning -List $warnings -Message 'driverquery failed; driverquery.csv can be incomplete.'
    }

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        SystemDrivers = $systemDrivers.Count
        RunningSystemDrivers = @($systemDrivers | Where-Object State -eq 'Running').Count
        AutoStartSystemDrivers = @($systemDrivers | Where-Object StartMode -eq 'Auto').Count
        SignedPnpDrivers = $signedDrivers.Count
    })
}

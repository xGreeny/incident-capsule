function Get-ICServiceEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $services = @()

    try {
        $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                State = $_.State
                Status = $_.Status
                Started = $_.Started
                StartMode = $_.StartMode
                StartName = $_.StartName
                PathName = $_.PathName
                ProcessId = $_.ProcessId
                ServiceType = $_.ServiceType
                AcceptPause = $_.AcceptPause
                AcceptStop = $_.AcceptStop
                DesktopInteract = $_.DesktopInteract
                DelayedAutoStart = Get-ICPropertyValue -InputObject $_ -Name 'DelayedAutoStart'
                ExitCode = $_.ExitCode
                ServiceSpecificExitCode = $_.ServiceSpecificExitCode
                Description = $_.Description
            }
        } | Sort-Object Name)
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Service inventory: $($_.Exception.Message)" }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Services -RelativePath 'evidence/services/services.json' -Data $services -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        ServiceCount = $services.Count
        RunningServices = @($services | Where-Object State -eq 'Running').Count
        AutoStartServices = @($services | Where-Object StartMode -eq 'Auto').Count
        StoppedAutoStartServices = @($services | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }).Count
    })
}

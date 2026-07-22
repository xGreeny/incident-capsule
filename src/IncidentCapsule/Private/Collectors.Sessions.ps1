function Get-ICSessionEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $logonSessions = @()
    try {
        $logonSessions = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop |
            Where-Object { $_.LogonType -in @(2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13) } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    LogonId = $_.LogonId
                    LogonType = $_.LogonType
                    AuthenticationPackage = $_.AuthenticationPackage
                    LogonServer = Get-ICPropertyValue -InputObject $_ -Name 'LogonServer'
                    StartTimeUtc = ConvertTo-ICIso8601 -Value $_.StartTime
                }
            } |
            Sort-Object StartTimeUtc)
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Logon sessions: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Sessions -RelativePath 'evidence/sessions/logon-sessions.json' -Data $logonSessions -Csv)

    $profiles = @()
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.Loaded } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    SID = $_.SID
                    LocalPath = $_.LocalPath
                    Loaded = $_.Loaded
                    Special = $_.Special
                    Status = $_.Status
                    RefCount = $_.RefCount
                    LastUseTimeUtc = ConvertTo-ICIso8601 -Value $_.LastUseTime
                }
            })
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Loaded profiles: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Sessions -RelativePath 'evidence/sessions/loaded-profiles.json' -Data $profiles -Csv)

    foreach ($commandDefinition in @(
        @{ Name = 'quser.exe'; RelativePath = 'evidence/sessions/quser.txt'; Arguments = @() },
        @{ Name = 'qwinsta.exe'; RelativePath = 'evidence/sessions/qwinsta.txt'; Arguments = @() }
    )) {
        $native = Export-ICNativeCommandOutput -Context $Context -RelativePath $commandDefinition.RelativePath -FilePath (Get-ICSystemExecutable -Name $commandDefinition.Name) -ArgumentList $commandDefinition.Arguments
        [void]$files.Add($native.Path)
        if ($null -ne $native.Error -or ($null -ne $native.ExitCode -and $native.ExitCode -ne 0)) {
            Add-ICCollectorWarning -List $warnings -Message "$($commandDefinition.Name) did not return a complete session view."
        }
    }

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        LogonSessions = $logonSessions.Count
        InteractiveLogons = @($logonSessions | Where-Object LogonType -in @(2, 7, 10, 11, 12, 13)).Count
        NetworkLogons = @($logonSessions | Where-Object LogonType -eq 3).Count
        LoadedProfiles = $profiles.Count
    })
}

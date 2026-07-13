function Get-ICHotfixEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $qfe = @()
    $history = @()

    try {
        $qfe = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                HotFixID = $_.HotFixID
                Description = $_.Description
                Caption = $_.Caption
                InstalledBy = $_.InstalledBy
                InstalledOn = [string]$_.InstalledOn
                ServicePackInEffect = $_.ServicePackInEffect
                Status = $_.Status
            }
        } | Sort-Object HotFixID)
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "QFE inventory: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Hotfixes -RelativePath 'evidence/hotfixes/qfe.json' -Data $qfe -Csv)

    if ($Context.Configuration.CollectWindowsUpdateHistory) {
        $session = $null
        $searcher = $null
        try {
            $session = New-Object -ComObject 'Microsoft.Update.Session'
            $searcher = $session.CreateUpdateSearcher()
            $total = $searcher.GetTotalHistoryCount()
            $count = [math]::Min([int]$total, [int]$Context.Configuration.MaximumWindowsUpdateHistory)
            if ($count -gt 0) {
                $history = @($searcher.QueryHistory(0, $count) | ForEach-Object {
                    [pscustomobject][ordered]@{
                        DateUtc = ConvertTo-ICIso8601 -Value $_.Date
                        Title = $_.Title
                        Description = $_.Description
                        Operation = $_.Operation
                        ResultCode = $_.ResultCode
                        HResult = ('0x{0:X8}' -f ($_.HResult -band 0xffffffffL))
                        UnmappedResultCode = $_.UnmappedResultCode
                        ClientApplicationID = $_.ClientApplicationID
                        ServerSelection = $_.ServerSelection
                        ServiceID = [string]$_.ServiceID
                        SupportUrl = $_.SupportUrl
                        UpdateIdentity = if ($null -ne $_.UpdateIdentity) { [ordered]@{ UpdateID = $_.UpdateIdentity.UpdateID; RevisionNumber = $_.UpdateIdentity.RevisionNumber } } else { $null }
                    }
                })
            }
            if ($total -gt $count) {
                Add-ICCollectorWarning -List $warnings -Message "Windows Update history was bounded at $count of $total entries."
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Windows Update history: $($_.Exception.Message)" }
        finally {
            if ($null -ne $searcher -and [System.Runtime.InteropServices.Marshal]::IsComObject($searcher)) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($searcher) }
            if ($null -ne $session -and [System.Runtime.InteropServices.Marshal]::IsComObject($session)) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($session) }
        }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Hotfixes -RelativePath 'evidence/hotfixes/windows-update-history.json' -Data $history -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        QfeEntries = $qfe.Count
        WindowsUpdateHistoryEntries = $history.Count
    })
}

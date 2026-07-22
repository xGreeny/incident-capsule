function Get-ICScheduledTaskEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $taskRecords = New-Object System.Collections.ArrayList
    $taskCsv = New-Object System.Collections.ArrayList
    $xmlCount = 0

    if (-not (Test-ICCommandAvailable -Name 'Get-ScheduledTask')) {
        Add-ICCollectorWarning -List $warnings -Message 'ScheduledTasks cmdlets are unavailable.'
        Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector ScheduledTasks -RelativePath 'evidence/scheduled-tasks/tasks.json' -Data @())
        return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{ ScheduledTasks = 0; TaskXmlFiles = 0 })
    }

    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop | Sort-Object TaskPath, TaskName) }
    catch { Add-ICCollectorWarning -List $warnings -Message "Scheduled task inventory: $($_.Exception.Message)" }

    foreach ($task in $tasks) {
        # One malformed task must not erase the remaining task evidence.
        try {
            $info = $null
            try { $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop }
            catch { Add-ICCollectorWarning -List $warnings -Message "Task info '$($task.TaskPath)$($task.TaskName)': $($_.Exception.Message)" }

            $actions = @($task.Actions | ForEach-Object {
                [ordered]@{
                    Type = [string](Get-ICPropertyValue -InputObject (Get-ICPropertyValue -InputObject $_ -Name 'CimClass') -Name 'CimClassName')
                    Execute = Get-ICPropertyValue -InputObject $_ -Name 'Execute'
                    Arguments = Get-ICPropertyValue -InputObject $_ -Name 'Arguments'
                    WorkingDirectory = Get-ICPropertyValue -InputObject $_ -Name 'WorkingDirectory'
                    ClassId = Get-ICPropertyValue -InputObject $_ -Name 'ClassId'
                    Data = Get-ICPropertyValue -InputObject $_ -Name 'Data'
                }
            })

            $triggers = @($task.Triggers | ForEach-Object {
                [ordered]@{
                    Type = [string](Get-ICPropertyValue -InputObject (Get-ICPropertyValue -InputObject $_ -Name 'CimClass') -Name 'CimClassName')
                    Enabled = Get-ICPropertyValue -InputObject $_ -Name 'Enabled'
                    StartBoundary = Get-ICPropertyValue -InputObject $_ -Name 'StartBoundary'
                    EndBoundary = Get-ICPropertyValue -InputObject $_ -Name 'EndBoundary'
                    Delay = Get-ICPropertyValue -InputObject $_ -Name 'Delay'
                    RandomDelay = Get-ICPropertyValue -InputObject $_ -Name 'RandomDelay'
                    UserId = Get-ICPropertyValue -InputObject $_ -Name 'UserId'
                    Subscription = Get-ICPropertyValue -InputObject $_ -Name 'Subscription'
                    RepetitionInterval = Get-ICPropertyValue -InputObject (Get-ICPropertyValue -InputObject $_ -Name 'Repetition') -Name 'Interval'
                    RepetitionDuration = Get-ICPropertyValue -InputObject (Get-ICPropertyValue -InputObject $_ -Name 'Repetition') -Name 'Duration'
                    StopAtDurationEnd = Get-ICPropertyValue -InputObject (Get-ICPropertyValue -InputObject $_ -Name 'Repetition') -Name 'StopAtDurationEnd'
                }
            })

            $record = [pscustomobject][ordered]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = [string]$task.State
                Author = $task.Author
                Description = $task.Description
                URI = $task.URI
                Hidden = Get-ICPropertyValue -InputObject $task.Settings -Name 'Hidden'
                Enabled = Get-ICPropertyValue -InputObject $task.Settings -Name 'Enabled'
                ExecutionTimeLimit = Get-ICPropertyValue -InputObject $task.Settings -Name 'ExecutionTimeLimit'
                MultipleInstances = [string](Get-ICPropertyValue -InputObject $task.Settings -Name 'MultipleInstances')
                RunOnlyIfIdle = Get-ICPropertyValue -InputObject $task.Settings -Name 'RunOnlyIfIdle'
                RunOnlyIfNetworkAvailable = Get-ICPropertyValue -InputObject $task.Settings -Name 'RunOnlyIfNetworkAvailable'
                WakeToRun = Get-ICPropertyValue -InputObject $task.Settings -Name 'WakeToRun'
                Principal = [ordered]@{
                    UserId = Get-ICPropertyValue -InputObject $task.Principal -Name 'UserId'
                    GroupId = Get-ICPropertyValue -InputObject $task.Principal -Name 'GroupId'
                    DisplayName = Get-ICPropertyValue -InputObject $task.Principal -Name 'DisplayName'
                    LogonType = [string](Get-ICPropertyValue -InputObject $task.Principal -Name 'LogonType')
                    RunLevel = [string](Get-ICPropertyValue -InputObject $task.Principal -Name 'RunLevel')
                    ProcessTokenSidType = [string](Get-ICPropertyValue -InputObject $task.Principal -Name 'ProcessTokenSidType')
                    RequiredPrivilege = Get-ICPropertyValue -InputObject $task.Principal -Name 'RequiredPrivilege'
                }
                Actions = $actions
                Triggers = $triggers
                LastRunTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $info -Name 'LastRunTime')
                NextRunTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $info -Name 'NextRunTime')
                LastTaskResult = Get-ICPropertyValue -InputObject $info -Name 'LastTaskResult'
                NumberOfMissedRuns = Get-ICPropertyValue -InputObject $info -Name 'NumberOfMissedRuns'
            }
            [void]$taskRecords.Add($record)

            [void]$taskCsv.Add([pscustomobject][ordered]@{
                TaskPath = $task.TaskPath
                TaskName = $task.TaskName
                State = [string]$task.State
                Principal = [string](Get-ICPropertyValue -InputObject $task.Principal -Name 'UserId')
                RunLevel = [string](Get-ICPropertyValue -InputObject $task.Principal -Name 'RunLevel')
                Hidden = Get-ICPropertyValue -InputObject $task.Settings -Name 'Hidden'
                ActionSummary = ($actions | ForEach-Object { "$(Get-ICPropertyValue -InputObject $_ -Name 'Execute') $(Get-ICPropertyValue -InputObject $_ -Name 'Arguments')" }) -join ' | '
                TriggerTypes = ($triggers | ForEach-Object { Get-ICPropertyValue -InputObject $_ -Name 'Type' }) -join ','
                LastRunTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $info -Name 'LastRunTime')
                NextRunTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $info -Name 'NextRunTime')
                LastTaskResult = Get-ICPropertyValue -InputObject $info -Name 'LastTaskResult'
            })

            if ($Context.Configuration.ExportScheduledTaskXml) {
                try {
                    $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
                    $identity = "$($task.TaskPath)$($task.TaskName)"
                    $safeName = ConvertTo-ICSafeFileName -Value ($identity.Trim('\') -replace '\\', '_') -MaximumLength 90
                    $digest = Get-ICShortHash -Value $identity -Length 10
                    $xmlPath = Join-Path $Context.RootPath ("evidence/scheduled-tasks/xml/{0}-{1}.xml" -f $safeName, $digest)
                    [void](Write-ICUtf8File -Path $xmlPath -Content ([string]$xml))
                    [void]$files.Add($xmlPath)
                    $xmlCount++
                }
                catch { Add-ICCollectorWarning -List $warnings -Message "Task XML '$($task.TaskPath)$($task.TaskName)': $($_.Exception.Message)" }
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Task '$($task.TaskPath)$($task.TaskName)': $($_.Exception.Message)" }
    }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector ScheduledTasks -RelativePath 'evidence/scheduled-tasks/tasks.json' -Data @($taskRecords))
    $csvPath = Join-Path $Context.RootPath 'evidence/scheduled-tasks/tasks.csv'
    [void](Write-ICCsvFile -Path $csvPath -InputObject @($taskCsv) -SpreadsheetSafe ([bool](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'SpreadsheetSafeCsv' -Default $true)))
    [void]$files.Add($csvPath)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        ScheduledTasks = $taskRecords.Count
        RunningTasks = @($taskRecords | Where-Object State -eq 'Running').Count
        HiddenTasks = @($taskRecords | Where-Object Hidden -eq $true).Count
        TaskXmlFiles = $xmlCount
    })
}

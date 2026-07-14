function Get-ICDirectorySize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return 0L
    }

    $total = 0L
    foreach ($file in Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue) {
        $total += [int64]$file.Length
    }
    return $total
}

function Get-ICCapsuleBudgetState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $maximumBytes = [int64](Get-ICPropertyValue -InputObject $Context.Configuration -Name 'MaximumCapsuleBytes' -Default 5368709120L)
    $currentBytes = Get-ICDirectorySize -Path $Context.RootPath
    return [pscustomobject][ordered]@{
        CurrentBytes   = $currentBytes
        MaximumBytes   = $maximumBytes
        RemainingBytes = [math]::Max(0L, $maximumBytes - $currentBytes)
        IsWithinBudget = $currentBytes -le $maximumBytes
        IsAtBudget     = $currentBytes -ge $maximumBytes
    }
}

function Add-ICSkippedCollectorResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Reason
    )

    $definition = $script:ICCollectorDefinitions[$Name]
    $timestamp = [datetime]::UtcNow.ToString('o')
    $result = [pscustomobject][ordered]@{
        name                 = $Name
        description          = [string]$definition.Description
        status               = 'Skipped'
        startedAtUtc         = $timestamp
        completedAtUtc       = $timestamp
        durationMilliseconds = 0
        outputFiles          = @()
        warnings             = @($Reason)
        error                = $null
        metrics              = [ordered]@{}
        issues               = @(
            New-ICStructuredIssue `
                -Code 'LIMIT_REACHED' `
                -Severity Warning `
                -Component $Name `
                -Message $Reason
        )
    }
    [void]$Context.CollectorResults.Add($result)
    Write-ICLog -Context $Context -Level WARN -Component $Name -Message $Reason
    return $result
}

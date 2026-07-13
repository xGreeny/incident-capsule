function Get-ICSystemExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $candidate = Join-Path $env:SystemRoot (Join-Path 'System32' $Name)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) {
        return $command.Source
    }

    return $Name
}

function Get-ICCount {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    return @($Value).Count
}

function Add-ICCollectorWarning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$List,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not [string]::IsNullOrWhiteSpace($Message) -and $Message -notin $List) {
        [void]$List.Add($Message)
    }
}

function Add-ICOutputFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$List,

        [AllowNull()]
        [object[]]$Path
    )

    foreach ($item in @($Path)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            [void]$List.Add([string]$item)
        }
    }
}

function Get-ICRegistryPolicyObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path
    )

    return @(Get-ICRegistryValues -Path $Path)
}

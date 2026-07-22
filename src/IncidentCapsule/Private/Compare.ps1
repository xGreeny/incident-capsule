# Curated set of stable evidence sources worth diffing between two capsules of
# the same host. Volatile sources (processes, live network endpoints, event
# summaries, timeline) are intentionally excluded: their churn would bury the
# meaningful persistence-, account-, and inventory-level changes.
function Get-ICComparisonSpec {
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{ Key = 'Services';           Source = 'evidence/services/services.json';                    Identity = @('Name');                 Label = 'Windows services' }
        [pscustomobject]@{ Key = 'ScheduledTasks';     Source = 'evidence/scheduled-tasks/tasks.json';               Identity = @('TaskPath', 'TaskName'); Label = 'Scheduled tasks' }
        [pscustomobject]@{ Key = 'InstalledSoftware';  Source = 'evidence/software/installed-software.json';         Identity = @('Scope', 'KeyName');     Label = 'Installed software' }
        [pscustomobject]@{ Key = 'RegistryAutoruns';   Source = 'evidence/persistence/registry-autoruns.json';       Identity = @('Key', 'ValueName');     Label = 'Autorun registry values' }
        [pscustomobject]@{ Key = 'LocalUsers';         Source = 'evidence/identities/local-users.json';              Identity = @('SID');                  Label = 'Local users' }
        [pscustomobject]@{ Key = 'LocalGroups';        Source = 'evidence/identities/local-groups.json';             Identity = @('SID');                  Label = 'Local groups' }
        [pscustomobject]@{ Key = 'Certificates';       Source = 'evidence/certificates/certificate-stores.json';     Identity = @('Store', 'Thumbprint');  Label = 'Certificate trust stores' }
        [pscustomobject]@{ Key = 'SystemDrivers';      Source = 'evidence/drivers/system-drivers.json';              Identity = @('Name');                 Label = 'System drivers' }
    )
}

function Get-ICRecordIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Record,

        [Parameter(Mandatory)]
        [string[]]$IdentityFields
    )

    $parts = foreach ($field in $IdentityFields) {
        $value = Get-ICPropertyValue -InputObject $Record -Name $field
        '{0}={1}' -f $field, ([string]$value)
    }
    return ($parts -join '|')
}

function Compare-ICEvidenceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Baseline,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Current,

        [Parameter(Mandatory)]
        [string[]]$IdentityFields
    )

    $baselineIndex = [ordered]@{}
    foreach ($record in @($Baseline)) {
        if ($null -eq $record) { continue }
        $identity = Get-ICRecordIdentity -Record $record -IdentityFields $IdentityFields
        if (-not $baselineIndex.Contains($identity)) { $baselineIndex[$identity] = $record }
    }
    $currentIndex = [ordered]@{}
    foreach ($record in @($Current)) {
        if ($null -eq $record) { continue }
        $identity = Get-ICRecordIdentity -Record $record -IdentityFields $IdentityFields
        if (-not $currentIndex.Contains($identity)) { $currentIndex[$identity] = $record }
    }

    $added = New-Object System.Collections.ArrayList
    $removed = New-Object System.Collections.ArrayList
    $changed = New-Object System.Collections.ArrayList

    foreach ($identity in $currentIndex.Keys) {
        if (-not $baselineIndex.Contains($identity)) {
            [void]$added.Add([pscustomobject][ordered]@{ identity = $identity; current = $currentIndex[$identity] })
        }
    }
    foreach ($identity in $baselineIndex.Keys) {
        if (-not $currentIndex.Contains($identity)) {
            [void]$removed.Add([pscustomobject][ordered]@{ identity = $identity; baseline = $baselineIndex[$identity] })
            continue
        }

        $baselineJson = ConvertTo-Json -InputObject $baselineIndex[$identity] -Depth 20 -Compress
        $currentJson = ConvertTo-Json -InputObject $currentIndex[$identity] -Depth 20 -Compress
        if ($baselineJson -cne $currentJson) {
            $changedFields = New-Object System.Collections.ArrayList
            $names = @($baselineIndex[$identity].PSObject.Properties.Name) + @($currentIndex[$identity].PSObject.Properties.Name) | Select-Object -Unique
            foreach ($name in $names) {
                $before = Get-ICPropertyValue -InputObject $baselineIndex[$identity] -Name $name
                $after = Get-ICPropertyValue -InputObject $currentIndex[$identity] -Name $name
                $beforeJson = ConvertTo-Json -InputObject $before -Depth 20 -Compress
                $afterJson = ConvertTo-Json -InputObject $after -Depth 20 -Compress
                if ($beforeJson -cne $afterJson) {
                    [void]$changedFields.Add([pscustomobject][ordered]@{ field = $name; baseline = $before; current = $after })
                }
            }
            [void]$changed.Add([pscustomobject][ordered]@{
                identity      = $identity
                changedFields = @($changedFields)
            })
        }
    }

    return [pscustomobject][ordered]@{
        Added   = @($added)
        Removed = @($removed)
        Changed = @($changed)
    }
}

function Get-ICCapsuleEvidenceData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CapsuleRoot,

        [Parameter(Mandatory)]
        [string]$Source
    )

    $path = Join-Path $CapsuleRoot ($Source -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ Available = $false; Data = @() }
    }

    try {
        $envelope = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Available = $false; Data = @() }
    }

    if (-not (Test-ICObjectProperty -InputObject $envelope -Name 'data')) {
        return [pscustomobject]@{ Available = $false; Data = @() }
    }
    return [pscustomobject]@{ Available = $true; Data = @($envelope.data) }
}

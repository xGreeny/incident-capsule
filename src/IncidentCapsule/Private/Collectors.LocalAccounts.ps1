function Get-ICLocalAccountEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $users = @()
    $groups = @()
    $members = @()

    if (Test-ICCommandAvailable -Name 'Get-LocalUser') {
        try {
            $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    SID = [string]$_.SID
                    Enabled = $_.Enabled
                    Description = $_.Description
                    FullName = $_.FullName
                    AccountExpiresUtc = ConvertTo-ICIso8601 -Value $_.AccountExpires
                    PasswordLastSetUtc = ConvertTo-ICIso8601 -Value $_.PasswordLastSet
                    PasswordExpiresUtc = ConvertTo-ICIso8601 -Value $_.PasswordExpires
                    UserMayChangePassword = $_.UserMayChangePassword
                    PasswordRequired = $_.PasswordRequired
                    LastLogonUtc = ConvertTo-ICIso8601 -Value $_.LastLogon
                    PrincipalSource = [string]$_.PrincipalSource
                }
            } | Sort-Object Name)
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Local users: $($_.Exception.Message)" }

        try {
            $groups = @(Get-LocalGroup -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    SID = [string]$_.SID
                    Description = $_.Description
                    PrincipalSource = [string]$_.PrincipalSource
                }
            } | Sort-Object Name)
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Local groups: $($_.Exception.Message)" }

        foreach ($group in $groups) {
            try {
                $groupMembers = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Group = $group.Name
                        GroupSID = $group.SID
                        Name = $_.Name
                        SID = [string]$_.SID
                        ObjectClass = $_.ObjectClass
                        PrincipalSource = [string]$_.PrincipalSource
                    }
                })
                $members += $groupMembers
            }
            catch {
                Add-ICCollectorWarning -List $warnings -Message "Local group '$($group.Name)' membership: $($_.Exception.Message)"
            }
        }
    }
    else {
        Add-ICCollectorWarning -List $warnings -Message 'Microsoft.PowerShell.LocalAccounts cmdlets are unavailable; CIM fallback provides basic inventory without reliable memberships.'
        try {
            $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    SID = $_.SID
                    Disabled = $_.Disabled
                    Lockout = $_.Lockout
                    Description = $_.Description
                    FullName = $_.FullName
                    PasswordChangeable = $_.PasswordChangeable
                    PasswordExpires = $_.PasswordExpires
                    PasswordRequired = $_.PasswordRequired
                    Status = $_.Status
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "CIM local users: $($_.Exception.Message)" }
        try {
            $groups = @(Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    SID = $_.SID
                    Description = $_.Description
                    Status = $_.Status
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "CIM local groups: $($_.Exception.Message)" }
    }

    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector LocalAccounts -RelativePath 'evidence/identities/local-users.json' -Data $users -Csv)
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector LocalAccounts -RelativePath 'evidence/identities/local-groups.json' -Data $groups -Csv)
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector LocalAccounts -RelativePath 'evidence/identities/local-group-members.json' -Data $members -Csv)

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        LocalUsers = $users.Count
        EnabledLocalUsers = @($users | Where-Object { (Get-ICPropertyValue -InputObject $_ -Name 'Enabled' -Default (-not (Get-ICPropertyValue -InputObject $_ -Name 'Disabled' -Default $false))) -eq $true }).Count
        LocalGroups = $groups.Count
        GroupMembershipRows = $members.Count
    })
}

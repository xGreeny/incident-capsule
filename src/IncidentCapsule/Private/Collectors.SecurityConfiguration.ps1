function Get-ICSecurityConfigurationEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList

    $firewallProfiles = @()
    if (Test-ICCommandAvailable -Name 'Get-NetFirewallProfile') {
        try {
            $firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    DefaultInboundAction = $_.DefaultInboundAction.ToString()
                    DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
                    AllowInboundRules = $_.AllowInboundRules
                    AllowLocalFirewallRules = $_.AllowLocalFirewallRules
                    AllowLocalIPsecRules = $_.AllowLocalIPsecRules
                    AllowUnicastResponseToMulticast = $_.AllowUnicastResponseToMulticast
                    NotifyOnListen = $_.NotifyOnListen
                    EnableStealthModeForIPsec = $_.EnableStealthModeForIPsec
                    LogFileName = $_.LogFileName
                    LogMaxSizeKilobytes = $_.LogMaxSizeKilobytes
                    LogAllowed = $_.LogAllowed
                    LogBlocked = $_.LogBlocked
                    LogIgnored = Get-ICPropertyValue -InputObject $_ -Name 'LogIgnored'
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Firewall profiles: $($_.Exception.Message)" }
    }
    else { Add-ICCollectorWarning -List $warnings -Message 'NetSecurity firewall cmdlets are unavailable.' }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector SecurityConfiguration -RelativePath 'evidence/security/firewall-profiles.json' -Data $firewallProfiles -Csv)

    $firewallRules = @()
    $firewallRuleTotal = $null
    if (Test-ICCommandAvailable -Name 'Get-NetFirewallRule') {
        try {
            $maximumFirewallRules = [int]$Context.Configuration.MaximumFirewallRules
            $boundedRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -First ($maximumFirewallRules + 1))
            $firewallRules = @($boundedRules | Select-Object -First $maximumFirewallRules | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Description = $_.Description
                    DisplayGroup = $_.DisplayGroup
                    Group = $_.Group
                    Enabled = $_.Enabled.ToString()
                    Profile = $_.Profile.ToString()
                    Platform = @($_.Platform)
                    Direction = $_.Direction.ToString()
                    Action = $_.Action.ToString()
                    EdgeTraversalPolicy = $_.EdgeTraversalPolicy.ToString()
                    LooseSourceMapping = $_.LooseSourceMapping
                    LocalOnlyMapping = $_.LocalOnlyMapping
                    Owner = $_.Owner
                    PrimaryStatus = $_.PrimaryStatus.ToString()
                    Status = $_.Status.ToString()
                    EnforcementStatus = $_.EnforcementStatus.ToString()
                    PolicyStoreSource = $_.PolicyStoreSource
                    PolicyStoreSourceType = $_.PolicyStoreSourceType.ToString()
                }
            })
            $firewallRuleTotal = $firewallRules.Count
            if ($boundedRules.Count -gt $firewallRules.Count) {
                $firewallRuleTotal = $null
                Add-ICCollectorWarning -List $warnings -Message "Firewall-rule export reached the configured limit of $($firewallRules.Count) rules; additional rules exist."
            }
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Firewall rules: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector SecurityConfiguration -RelativePath 'evidence/security/firewall-rules.json' -Data $firewallRules -Csv)

    $securityRegistry = @(Get-ICRegistryValues -Path @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ) -ValueName @(
        'EnableLUA', 'ConsentPromptBehaviorAdmin', 'PromptOnSecureDesktop', 'FilterAdministratorToken',
        'LocalAccountTokenFilterPolicy', 'fDenyTSConnections', 'UserAuthentication', 'SecurityLayer', 'MinEncryptionLevel',
        'LmCompatibilityLevel', 'RunAsPPL', 'DisableDomainCreds', 'NoLMHash', 'RestrictAnonymous', 'RestrictAnonymousSAM',
        'UseLogonCredential', 'RequireSecuritySignature', 'EnableSecuritySignature', 'EnablePlainTextPassword'
    ))
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector SecurityConfiguration -RelativePath 'evidence/security/uac-rdp-lsa.json' -Data $securityRegistry -Csv)

    $deviceGuard = @()
    try {
        $deviceGuard = @(Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                AvailableSecurityProperties = @($_.AvailableSecurityProperties)
                CodeIntegrityPolicyEnforcementStatus = $_.CodeIntegrityPolicyEnforcementStatus
                InstanceIdentifier = $_.InstanceIdentifier
                RequiredSecurityProperties = @($_.RequiredSecurityProperties)
                SecurityFeaturesEnabled = @($_.SecurityFeaturesEnabled)
                SecurityServicesConfigured = @($_.SecurityServicesConfigured)
                SecurityServicesRunning = @($_.SecurityServicesRunning)
                UsermodeCodeIntegrityPolicyEnforcementStatus = $_.UsermodeCodeIntegrityPolicyEnforcementStatus
                Version = $_.Version
                VirtualizationBasedSecurityStatus = $_.VirtualizationBasedSecurityStatus
            }
        })
    }
    catch { Add-ICCollectorWarning -List $warnings -Message "Device Guard status: $($_.Exception.Message)" }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector SecurityConfiguration -RelativePath 'evidence/security/device-guard.json' -Data $deviceGuard)

    $auditPol = Export-ICNativeCommandOutput -Context $Context -RelativePath 'evidence/security/audit-policy.txt' -FilePath (Get-ICSystemExecutable -Name 'auditpol.exe') -ArgumentList @('/get', '/category:*', '/r')
    [void]$files.Add($auditPol.Path)
    if ($null -ne $auditPol.Error -or ($null -ne $auditPol.ExitCode -and $auditPol.ExitCode -ne 0)) {
        Add-ICCollectorWarning -List $warnings -Message 'auditpol export failed; inspect evidence/security/audit-policy.txt.'
    }

    $netsh = Export-ICNativeCommandOutput -Context $Context -RelativePath 'evidence/security/netsh-firewall-profiles.txt' -FilePath (Get-ICSystemExecutable -Name 'netsh.exe') -ArgumentList @('advfirewall', 'show', 'allprofiles')
    [void]$files.Add($netsh.Path)
    if ($null -ne $netsh.Error -or ($null -ne $netsh.ExitCode -and $netsh.ExitCode -ne 0)) {
        Add-ICCollectorWarning -List $warnings -Message 'netsh firewall profile export failed.'
    }

    $securityPolicyPath = Join-Path $Context.RootPath 'evidence/security/local-security-policy.inf'
    $secedit = Invoke-ICNativeCommand -FilePath (Get-ICSystemExecutable -Name 'secedit.exe') -ArgumentList @('/export', '/cfg', $securityPolicyPath, '/quiet') -Context $Context
    $seceditLogPath = Join-Path $Context.RootPath 'evidence/security/secedit-export.txt'
    [void](Write-ICUtf8File -Path $seceditLogPath -Content ((@(
        "# capturedAtUtc: $([datetime]::UtcNow.ToString('o'))",
        "# exitCode: $($secedit.ExitCode)",
        "# error: $($secedit.Error)",
        ''
    ) + @($secedit.Output)) -join [Environment]::NewLine))
    [void]$files.Add($seceditLogPath)
    if (Test-Path -LiteralPath $securityPolicyPath -PathType Leaf) {
        [void]$files.Add($securityPolicyPath)
    }
    else {
        Add-ICCollectorWarning -List $warnings -Message 'Local security policy export was not created; elevation can be required.'
    }

    if (Test-ICCommandAvailable -Name 'Get-AppLockerPolicy') {
        try {
            $xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $appLockerPath = Join-Path $Context.RootPath 'evidence/security/applocker-policy.xml'
            [void](Write-ICUtf8File -Path $appLockerPath -Content ([string]$xml))
            [void]$files.Add($appLockerPath)
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "AppLocker policy: $($_.Exception.Message)" }
    }

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        FirewallProfiles = $firewallProfiles.Count
        EnabledFirewallProfiles = @($firewallProfiles | Where-Object Enabled -eq $true).Count
        FirewallRulesTotal = $firewallRuleTotal
        FirewallRulesExported = $firewallRules.Count
        DeviceGuardRecords = $deviceGuard.Count
        LocalSecurityPolicyExported = Test-Path -LiteralPath $securityPolicyPath -PathType Leaf
    })
}

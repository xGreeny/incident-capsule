function Get-ICNetworkEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $warnings = New-Object System.Collections.ArrayList
    $files = New-Object System.Collections.ArrayList
    $processNames = @{}
    try {
        foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
            $processNames[[int]$process.Id] = $process.ProcessName
        }
    }
    catch { }

    $adapters = @()
    if (Test-ICCommandAvailable -Name 'Get-NetAdapter') {
        try {
            $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = $_.Name
                    InterfaceDescription = $_.InterfaceDescription
                    InterfaceIndex = $_.ifIndex
                    Status = $_.Status.ToString()
                    MacAddress = $_.MacAddress
                    LinkSpeed = $_.LinkSpeed
                    MediaType = $_.MediaType.ToString()
                    PhysicalMediaType = $_.PhysicalMediaType.ToString()
                    DriverDescription = $_.DriverDescription
                    DriverVersion = $_.DriverVersion
                    DriverDate = ConvertTo-ICIso8601 -Value $_.DriverDate
                    InterfaceGuid = $_.InterfaceGuid
                    Virtual = $_.Virtual
                    ConnectorPresent = $_.ConnectorPresent
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Network adapters: $($_.Exception.Message)" }
    }
    else { Add-ICCollectorWarning -List $warnings -Message 'Get-NetAdapter is unavailable.' }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/adapters.json' -Data $adapters -Csv)

    $addresses = @()
    if (Test-ICCommandAvailable -Name 'Get-NetIPAddress') {
        try {
            $addresses = @(Get-NetIPAddress -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    InterfaceAlias = $_.InterfaceAlias
                    InterfaceIndex = $_.InterfaceIndex
                    AddressFamily = $_.AddressFamily.ToString()
                    IPAddress = $_.IPAddress
                    PrefixLength = $_.PrefixLength
                    Type = $_.Type.ToString()
                    PrefixOrigin = $_.PrefixOrigin.ToString()
                    SuffixOrigin = $_.SuffixOrigin.ToString()
                    AddressState = $_.AddressState.ToString()
                    SkipAsSource = $_.SkipAsSource
                    ValidLifetime = $_.ValidLifetime.ToString()
                    PreferredLifetime = $_.PreferredLifetime.ToString()
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "IP addresses: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/ip-addresses.json' -Data $addresses -Csv)

    $routes = @()
    if (Test-ICCommandAvailable -Name 'Get-NetRoute') {
        try {
            $routes = @(Get-NetRoute -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    InterfaceAlias = $_.InterfaceAlias
                    InterfaceIndex = $_.InterfaceIndex
                    AddressFamily = $_.AddressFamily.ToString()
                    DestinationPrefix = $_.DestinationPrefix
                    NextHop = $_.NextHop
                    RouteMetric = $_.RouteMetric
                    InterfaceMetric = $_.InterfaceMetric
                    Protocol = $_.Protocol.ToString()
                    State = $_.State.ToString()
                    Store = $_.Store.ToString()
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Routes: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/routes.json' -Data $routes -Csv)

    $tcp = @()
    if (Test-ICCommandAvailable -Name 'Get-NetTCPConnection') {
        try {
            $tcp = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
                $ownerPid = [int]$_.OwningProcess
                [pscustomobject][ordered]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort = $_.RemotePort
                    State = $_.State.ToString()
                    AppliedSetting = (Get-ICPropertyValue -InputObject $_ -Name 'AppliedSetting')
                    OwningProcess = $ownerPid
                    ProcessName = if ($processNames.ContainsKey($ownerPid)) { $processNames[$ownerPid] } else { $null }
                    CreationTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $_ -Name 'CreationTime')
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "TCP connections: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/tcp-connections.json' -Data $tcp -Csv)

    $udp = @()
    if (Test-ICCommandAvailable -Name 'Get-NetUDPEndpoint') {
        try {
            $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
                $ownerPid = [int]$_.OwningProcess
                [pscustomobject][ordered]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    OwningProcess = $ownerPid
                    ProcessName = if ($processNames.ContainsKey($ownerPid)) { $processNames[$ownerPid] } else { $null }
                    CreationTimeUtc = ConvertTo-ICIso8601 -Value (Get-ICPropertyValue -InputObject $_ -Name 'CreationTime')
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "UDP endpoints: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/udp-endpoints.json' -Data $udp -Csv)

    $dnsServers = @()
    if (Test-ICCommandAvailable -Name 'Get-DnsClientServerAddress') {
        try {
            $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    InterfaceAlias = $_.InterfaceAlias
                    InterfaceIndex = $_.InterfaceIndex
                    AddressFamily = $_.AddressFamily.ToString()
                    ServerAddresses = @($_.ServerAddresses)
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "DNS server addresses: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/dns-servers.json' -Data $dnsServers)

    $dnsCache = @()
    if (Test-ICCommandAvailable -Name 'Get-DnsClientCache') {
        try {
            $dnsCache = @(Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Entry = $_.Entry
                    Name = $_.Name
                    Data = $_.Data
                    Type = $_.Type
                    Status = $_.Status
                    Section = $_.Section
                    TimeToLive = $_.TimeToLive
                    DataLength = $_.DataLength
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "DNS cache: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/dns-cache.json' -Data $dnsCache -Csv)

    $neighbors = @()
    if (Test-ICCommandAvailable -Name 'Get-NetNeighbor') {
        try {
            $neighbors = @(Get-NetNeighbor -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    InterfaceAlias = $_.InterfaceAlias
                    InterfaceIndex = $_.InterfaceIndex
                    AddressFamily = $_.AddressFamily.ToString()
                    IPAddress = $_.IPAddress
                    LinkLayerAddress = $_.LinkLayerAddress
                    State = $_.State.ToString()
                    Store = $_.Store.ToString()
                }
            })
        }
        catch { Add-ICCollectorWarning -List $warnings -Message "Neighbor cache: $($_.Exception.Message)" }
    }
    Add-ICOutputFiles -List $files -Path (Export-ICCollectorData -Context $Context -Collector Network -RelativePath 'evidence/network/neighbors.json' -Data $neighbors -Csv)

    $nativeCommands = @(
        @{ RelativePath = 'evidence/network/ipconfig-all.txt'; Name = 'ipconfig.exe'; Arguments = @('/all') },
        @{ RelativePath = 'evidence/network/route-print.txt'; Name = 'route.exe'; Arguments = @('print') },
        @{ RelativePath = 'evidence/network/arp-a.txt'; Name = 'arp.exe'; Arguments = @('-a') },
        @{ RelativePath = 'evidence/network/netstat-ano.txt'; Name = 'netstat.exe'; Arguments = @('-ano') }
    )
    foreach ($command in $nativeCommands) {
        $native = Export-ICNativeCommandOutput -Context $Context -RelativePath $command.RelativePath -FilePath (Get-ICSystemExecutable -Name $command.Name) -ArgumentList $command.Arguments
        [void]$files.Add($native.Path)
        if ($null -ne $native.Error -or ($null -ne $native.ExitCode -and $native.ExitCode -ne 0)) {
            Add-ICCollectorWarning -List $warnings -Message "$($command.Name) failed; inspect $($command.RelativePath)."
        }
    }

    return New-ICCollectorResultData -OutputFiles @($files) -Warnings @($warnings) -Metrics ([ordered]@{
        Adapters = $adapters.Count
        IPAddresses = $addresses.Count
        Routes = $routes.Count
        TcpConnections = $tcp.Count
        ListeningTcpEndpoints = @($tcp | Where-Object State -eq 'Listen').Count
        UdpEndpoints = $udp.Count
        DnsCacheRecords = $dnsCache.Count
        Neighbors = $neighbors.Count
    })
}

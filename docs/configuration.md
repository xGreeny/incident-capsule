# Configuration

Incident Capsule ships with three bounded profiles. A `.psd1` data file can replace specific settings while preserving the profile's collector set and defaults.

## Precedence

```text
Built-in profile
      ↓
ConfigurationPath overrides
      ↓
Collectors parameter replaces collector list
      ↓
ExcludeCollector removes names
```

## Supported keys

| Key | Type | Meaning |
|---|---|---|
| `Collectors` | `string[]` | Collector names to run |
| `EventLogs` | `string[]` | Event channels queried by the EventLogs collector |
| `EventLookbackHours` | positive integer | Time window for event summaries and EVTX query |
| `MaximumEventsPerLog` | positive integer | Maximum decoded events written per channel |
| `ExportEvtx` | Boolean | Export native `.evtx` files with `wevtutil` |
| `ExportScheduledTaskXml` | Boolean | Export task definitions as XML |
| `IncludeProcessCommandLines` | Boolean | Include process command lines in process evidence |
| `HashProcessExecutables` | Boolean | Hash unique running-process images and inspect signatures |
| `MaximumExecutableHashes` | positive integer | Upper bound for process-image hashing |
| `HashPersistenceFiles` | Boolean | Hash files found in startup folders |
| `CollectWmiSubscriptions` | Boolean | Query permanent WMI subscription classes |
| `CollectDefenderPreferences` | Boolean | Export Defender preferences, including exclusions and ASR configuration |
| `CollectWindowsUpdateHistory` | Boolean | Query bounded Windows Update history through the local COM interface |
| `MaximumWindowsUpdateHistory` | positive integer | Maximum update-history entries |
| `CollectSignedDrivers` | Boolean | Export signed PnP driver inventory |
| `MaximumSignedDrivers` | positive integer | Upper bound for signed-driver rows |
| `MaximumFirewallRules` | positive integer | Upper bound for exported firewall-rule metadata |
| `SpreadsheetSafeCsv` | Boolean | Prefix potentially active spreadsheet formulas in derived CSV views; JSON remains unchanged |
| `MaximumArchiveEntries` | positive integer | Maximum ZIP entries accepted during archive verification |
| `MaximumArchiveEntryBytes` | positive integer | Maximum expanded size of one archive entry |
| `MaximumArchiveExpandedBytes` | positive integer | Maximum total expanded archive size |
| `MaximumArchiveCompressionRatio` | positive integer | Maximum expanded-to-compressed ratio accepted for one entry |

Unknown settings are rejected. Numeric options are validated against both a positive lower bound and project-defined hard maximums. This prevents misspelled settings and intentionally extreme values from silently changing collection expectations.

## Curated Standard channels

The Standard profile attempts these channels when present:

```text
System
Application
Security
Windows PowerShell
Microsoft-Windows-PowerShell/Operational
Microsoft-Windows-Windows Defender/Operational
Microsoft-Windows-TaskScheduler/Operational
Microsoft-Windows-WMI-Activity/Operational
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
Microsoft-Windows-Sysmon/Operational
Microsoft-Windows-AppLocker/EXE and DLL
Microsoft-Windows-CodeIntegrity/Operational
Microsoft-Windows-Bits-Client/Operational
```

A missing or disabled channel is recorded as a warning. It does not fail the capsule.

## Example: focused identity and persistence collection

```powershell
Invoke-IncidentCapsule `
    -OutputPath 'C:\IR\Cases' `
    -CaseId 'IR-2026-0042' `
    -Collectors System,Sessions,LocalAccounts,ScheduledTasks,Persistence,PowerShell,EventLogs
```

## Example: custom data file

```powershell
@{
    EventLookbackHours         = 36
    MaximumEventsPerLog        = 1500
    ExportEvtx                 = $true
    IncludeProcessCommandLines = $false
    HashProcessExecutables     = $true
    MaximumExecutableHashes    = 100
    EventLogs = @(
        'System',
        'Security',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational'
    )
}
```

Save the object as `case-config.psd1` and pass it through `-ConfigurationPath`.

## Privacy-oriented collection

`examples/config.privacy-conscious.psd1` deliberately suppresses several high-value but sensitive sources. It is suitable when the operational question is narrow or data-minimization requirements take precedence. It is not equivalent to the Standard profile and can materially reduce investigative context.

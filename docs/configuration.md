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
| `MaximumCapsuleBytes` | positive integer | Stop launching additional collectors once the working capsule reaches this size |
| `MaximumEvtxBytesPerLog` | positive integer | Maximum retained size of each native EVTX export |
| `NativeCommandTimeoutSeconds` | positive integer | Wall-clock limit for each native command |
| `MaximumNativeOutputBytes` | positive integer | Combined standard-output and standard-error limit for each native command |
| `MaximumTimelineEntries` | positive integer | Maximum entries retained in the derived timeline index |
| `DataHandlingProfile` | `Full` or `Minimized` | Records the intended data scope and applies minimized defaults to sensitive options unless explicitly overridden |
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
| `MaximumEventMessageChars` | positive integer | Maximum characters retained per decoded event message in summaries; native EVTX exports are unaffected |
| `MaximumPrefetchFiles` | positive integer | Maximum prefetch files copied by the ExecutionArtifacts collector |
| `MaximumArtifactFileBytes` | positive integer | Per-file byte bound for copied artifact files (prefetch files, `setupapi.dev.log`) |
| `SpreadsheetSafeCsv` | Boolean | Prefix potentially active spreadsheet formulas in derived CSV views; JSON remains unchanged |
| `MaximumArchiveEntries` | positive integer | Maximum ZIP entries accepted during archive verification |
| `MaximumArchiveEntryBytes` | positive integer | Maximum expanded size of one archive entry |
| `MaximumArchiveExpandedBytes` | positive integer | Maximum total expanded archive size |
| `MaximumArchiveCompressionRatio` | positive integer | Maximum expanded-to-compressed ratio accepted for one entry |

Unknown settings are rejected. Numeric options are validated against both a positive lower bound and project-defined hard maximums. This prevents misspelled settings and intentionally extreme values from silently changing collection expectations.

## Built-in resource budgets

| Profile | Capsule | EVTX per channel | Native command | Native output | Timeline |
|---|---:|---:|---:|---:|---:|
| Minimal | 1 GiB | 64 MiB | 30 seconds | 10 MiB | 2,000 entries |
| Standard | 5 GiB | 256 MiB | 60 seconds | 25 MiB | 10,000 entries |
| Extended | 20 GiB | 1 GiB | 120 seconds | 100 MiB | 50,000 entries |

The limits bound acquisition work; they are not storage reservations. When a limit is reached, the capsule keeps useful output, records a structured `LIMIT_REACHED` issue, and marks affected work partial or skipped. Use `Test-IncidentCapsuleReadiness` before collection to inspect the effective values and destination headroom.

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
    MaximumCapsuleBytes        = 3221225472
    MaximumEvtxBytesPerLog     = 134217728
    NativeCommandTimeoutSeconds = 45
    MaximumNativeOutputBytes   = 20971520
    MaximumTimelineEntries     = 7500
    DataHandlingProfile        = 'Minimized'
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

`examples/config.privacy-conscious.psd1` sets `DataHandlingProfile = 'Minimized'` and deliberately suppresses several high-value but sensitive sources. It is suitable when the operational question is narrow or data-minimization requirements take precedence. It is not equivalent to the Standard profile and can materially reduce investigative context. Explicit values still win, so review the readiness result's `PrivacyScope` before acquisition.

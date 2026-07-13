# Troubleshooting

## A collector is `Partial`

Open `metadata/capsule.json` or `report/index.html` and review that collector's warnings. Common reasons are:

- the session is not elevated;
- a Windows feature or management module is absent;
- an event channel is disabled or does not exist on that edition;
- a security product other than Microsoft Defender is active;
- a provider denies access to protected objects;
- a domain controller has no local SAM equivalent for LocalAccounts;
- the configured lookback contains no events.

A partial collector is not automatically a failed capsule.

## Security EVTX is missing

Run the collection from an elevated session, verify that the Security channel exists, and review the EventLogs warning. The module does not bypass channel ACLs.

## `Get-MpComputerStatus` is unavailable

The Defender collector records a warning when the Defender PowerShell module is absent or disabled. This is expected on systems using another security product or on installations where Defender components were removed.

## Scheduled-task XML is incomplete

Protected tasks can deny `Export-ScheduledTask` to a non-elevated session. The task list can still contain readable metadata. Use elevation only under the approved response procedure.

## The archive is large

EVTX files dominate many capsules. Options:

```powershell
# Keep decoded summaries but suppress native EVTX
@{ ExportEvtx = $false }

# Reduce the lookback and decoded-event count
@{
    EventLookbackHours  = 12
    MaximumEventsPerLog = 250
}

# Run a focused collector set
-Collectors System,Processes,Network,Defender,EventLogs
```

Ensure the destination has room for both the working directory and ZIP. Use `-NoCompression` when only a directory is required, or `-RemoveWorkingDirectory` when only the archive should remain.

## Integrity verification reports unexpected files

The manifest covers the capsule at freeze time. Opening the directory in some tools can create metadata files; analysts can also add notes accidentally. Preserve the original and work from a copy. Unexpected files are reported separately from modified or missing expected files.

## Archive verification has no sidecar result

The embedded manifest can still be checked. `ArchiveHashValid` is `$null` when `<archive>.sha256` is absent. Recover the trusted sidecar from the acquisition location or case record before relying on transfer integrity.

## Module import is blocked

For a trusted, downloaded release, inspect the files and use the organization's normal execution-policy procedure. Do not disable security controls globally. A common local action after verification is:

```powershell
Get-ChildItem .\incident-capsule -Recurse -File | Unblock-File
Import-Module .\incident-capsule\src\IncidentCapsule\IncidentCapsule.psd1
```

## Report links do not open from the ZIP viewer

Extract the archive first. The report uses relative offline links to evidence files and is designed to be opened from `report/index.html` inside the extracted capsule.

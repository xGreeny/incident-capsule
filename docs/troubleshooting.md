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
Import-Module .\incident-capsule\IncidentCapsule\IncidentCapsule.psd1
```

The path above is for an extracted release. In a source checkout, use `src\IncidentCapsule\IncidentCapsule.psd1`. The root-level `Invoke-IncidentCapsule.ps1` launcher detects both layouts and reports every searched path if the module is missing.

## The package smoke test fails

Run `./build.ps1 -Task Package` on Windows with both Windows PowerShell 5.1 and PowerShell 7 (`pwsh.exe`) installed. The task deliberately tests the extracted ZIP, not the source tree. It checks the sidecar hash, package root name, module version, import path, launcher, focused System collection, and generated capsule integrity.

Common causes include:

- `pwsh.exe` is not on `PATH`;
- endpoint protection blocks scripts extracted beneath the temporary directory;
- the package launcher or module directory was renamed inside the staging tree;
- `ModuleVersion`, `$script:ICVersion`, and the matching changelog heading disagree;
- a tag was supplied that is not exactly `v<ModuleVersion>`.

Do not publish an archive by bypassing this test. Correct the environment or package layout and rebuild from a clean `out` directory.

## A tagged release workflow refuses to overwrite a release

Release assets are immutable by design. If the tag already has a GitHub release, the workflow stops instead of using `--clobber`. Correct the version, create a new tag, and rebuild. Published assets also receive a GitHub artifact attestation; verify it with a current GitHub CLI using `gh attestation verify <archive> --repo xGreeny/incident-capsule`.

## Report links do not open from the ZIP viewer

Extract the archive first. The report uses relative offline links to evidence files and is designed to be opened from `report/index.html` inside the extracted capsule.

# Readiness and handoff

Incident Capsule 1.1 separates three questions that should not be confused during first response:

1. **Is the host ready to run the requested acquisition?**
2. **What evidence was actually collected, omitted, or truncated?**
3. **Did the resulting artifact pass integrity verification?**

None of these answers is a verdict that the host is clean or compromised.

## Preflight readiness

`Test-IncidentCapsuleReadiness` accepts the same profile and scope controls as the collector without creating a capsule or contacting a network service.

```powershell
$readiness = Test-IncidentCapsuleReadiness `
    -OutputPath 'E:\Evidence' `
    -Profile Standard `
    -ConfigurationPath .\case-config.psd1

$readiness | Format-List Status,IsReady,IsElevated,OutputPath
$readiness.Checks | Format-Table Code,Category,Status,Message -AutoSize
$readiness.Configuration
```

The overall state is one of:

- `Ready`: no blocking or warning condition was found;
- `ReadyWithWarnings`: collection can start, but one or more sources can be partial;
- `Blocked`: a hard prerequisite such as the platform, output path, or configured storage budget failed.

Optional event channels and collector integrations are warnings rather than blockers. Stable check codes make the result suitable for runbooks and automation.

## Resource budgets

Profiles now include hard-validated operational budgets:

- `MaximumCapsuleBytes`;
- `MaximumEvtxBytesPerLog`;
- `NativeCommandTimeoutSeconds`;
- `MaximumNativeOutputBytes`;
- `MaximumTimelineEntries`;
- `MaximumArchiveEntries`, `MaximumArchiveEntryBytes`, `MaximumArchiveExpandedBytes`, and `MaximumArchiveCompressionRatio`;
- the existing event, hash, update, driver, and firewall limits.

Readiness reserves the configured capsule budget plus equivalent headroom when a ZIP archive will be created. A reached runtime limit is recorded as a partial or skipped source with the `LIMIT_REACHED` reason code; it is not silently treated as complete evidence.

## Data handling profile

Collection depth and data handling are separate decisions. `DataHandlingProfile` supports:

- `Full`: the collection profile's normal evidence settings;
- `Minimized`: suppresses process command lines, task XML, Defender preferences, and Windows Update history unless the configuration file explicitly opts a field back in.

The effective values always appear in readiness output, capsule metadata, and the report privacy-scope section.

## Collection coverage

Each capsule contains `metadata/coverage.json`. It records:

- every known collector, including collectors not selected;
- selected, succeeded, partial, failed, skipped, and not-run states;
- structured issues with a stable code, severity, component, and message;
- the effective privacy scope and resource limits.

Human-readable collector warnings remain in `capsule.json` for compatibility. The structured issue list provides a stable automation contract.

Common runtime reason codes include:

| Code | Meaning |
|---|---|
| `ACCESS_DENIED` | The current identity could not read a source. |
| `CHANNEL_UNAVAILABLE` | A configured event channel does not exist or cannot be inspected. |
| `COMMAND_UNAVAILABLE` | An optional inbox command or PowerShell cmdlet is unavailable. |
| `LIMIT_REACHED` | A configured time, size, row, or output limit stopped or truncated work. |
| `TIMEOUT` | A native command exceeded its runtime budget. |
| `COLLECTION_ERROR` | A source failed for another recorded reason. |

## Derived timeline

`analysis/timeline.json` and `analysis/timeline.csv` provide a bounded chronological index of timestamped records already present in the capsule. Each entry retains its collector, source evidence path, zero-based `sourceIndex` within that evidence envelope, timestamp property, and available record identifiers.

The timeline:

- performs no additional host query;
- applies no detection rule or risk score;
- keeps the newest records when `MaximumTimelineEntries` is reached;
- bounds candidate retention while scanning instead of accumulating every timestamp in memory;
- marks truncation explicitly;
- counts unreadable JSON sources and invalid timestamp values without treating them as indexed evidence.

The JSON file remains the canonical derived representation. CSV is formula-safe for spreadsheet review; the original evidence values remain unchanged in collector JSON.

## Safe verification policy

The verifier treats ZIPs and manifests as untrusted input. It rejects unsafe or duplicate paths and symbolic-link entry metadata before filesystem access, cross-checks the conventional checksum list, and applies limits for entry count, individual entries, total expanded size, and compression ratio before extraction.

For custody-sensitive workflows, require the adjacent archive sidecar:

```powershell
Test-IncidentCapsuleIntegrity `
    -Path .\IC_CASE_HOST_20260714T100000Z.zip `
    -RequireSidecar
```

The default expanded-size ceiling is 20 GiB, matching the largest built-in profile. If collection used a custom `MaximumCapsuleBytes` above that value, the receiving analyst must pass the same approved value through `-MaximumArchiveExpandedBytes`; do not raise it for an untrusted archive without confirming storage headroom.

Successful archive finalization also writes an external `.zip.verification.json` receipt containing the applied policy and verification counts. `-RemoveWorkingDirectory` is permitted only after the archive checksum, checksum list, and embedded manifest have all been verified. Preserve the sidecar hash and receipt in a separate trusted case record when authenticity matters.

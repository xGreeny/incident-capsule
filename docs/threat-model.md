# Threat model

## Assets

Incident Capsule protects the operational usefulness of:

- collected host-state evidence;
- collector status and warnings;
- case and acquisition metadata;
- the offline report;
- file and archive checksums.

## Trust boundaries

```text
Operator and trusted module
        │
        ▼
Compromised or suspected Windows host
        │
        ▼
Chosen evidence destination
        │
        ▼
Transfer channel and analysis workstation
```

The module executes on the system being examined. That system can already be compromised; local APIs, binaries, providers, and returned data can therefore be tampered with.

## Threats addressed

### Accidental omission hidden by a "successful" run

Each collector reports its own state, warnings, and outputs. Missing channels or denied providers are visible in `capsule.json`, the log, and the report.

### Accidental modification after collection

The embedded SHA-256 manifest identifies missing, changed, and unexpected files. The archive sidecar detects changes to the ZIP during storage or transfer.

### Unbounded collection

Profiles set explicit event windows, event limits, update-history limits, firewall-rule limits, and executable/driver hash limits. Configuration validation rejects invalid values.

### Unsafe remediation during evidence gathering

The collector performs no isolation, termination, quarantine, clearing, or configuration change. It does not accept arbitrary remote hosts or native commands from the command line.

### Hidden network dependency

The report is offline. No collector uploads evidence or contacts a service. No JavaScript, font, image, or telemetry resource is loaded from the network by the generated report.

## Threats not addressed

### Host-level deception

A kernel implant, API hook, malicious WMI provider, replaced inbox binary, or EDR tampering can cause incomplete or false output. Cross-check important findings with EDR telemetry, memory analysis, network evidence, or offline disk analysis.

### Authenticity against a writer

An actor who can modify the capsule and checksum files can recalculate SHA-256. Preserve the archive checksum in a separate trusted system or apply organizational digital signatures.

### Complete forensic acquisition

The project does not capture memory, pagefile, hibernation data, unallocated disk space, alternate data streams across the filesystem, full registry hives, or every user profile. It is not a forensic image.

### Remote compromise response

The project does not isolate endpoints, block indicators, rotate credentials, or deploy remotely. Those actions belong to response orchestration and should remain separate from evidence acquisition.

### Confidentiality

The ZIP is not encrypted. Confidentiality depends on the chosen filesystem, transfer channel, access controls, and organizational handling process.

## Abuse resistance

The tool avoids features that would make it a general remote reconnaissance framework:

- no remote-computer parameter;
- no arbitrary command execution;
- no active network scanning;
- no credential collection;
- no browser or PowerShell history contents;
- no persistence or deployment mechanism.

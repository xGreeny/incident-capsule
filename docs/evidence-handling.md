# Evidence handling

Incident Capsule creates a triage artifact, not a full forensic image. Its value depends on controlled collection and handling.

## Before collection

- Confirm authority to examine the host and collect user/process/event data.
- Record the case identifier, operator, host, date/time, and reason for collection in the incident record.
- Prefer a destination on an encrypted, access-controlled volume with sufficient capacity.
- Consider whether running new software on the host is acceptable under the response plan.
- If volatile evidence must be acquired in a specific order, coordinate Incident Capsule with memory, EDR, or network acquisition rather than improvising.

## During collection

- Use a trusted copy of the repository or a tagged release whose checksum has already been verified.
- Run elevated only when permitted and necessary.
- Do not browse or alter collected evidence while acquisition is in progress.
- Record collector warnings; missing evidence is itself operationally relevant.
- Avoid writing the capsule to the suspected system disk when removable or remote evidence storage is available and approved.

## After collection

1. Verify the working directory or ZIP with `Test-IncidentCapsuleIntegrity`.
2. Record the archive SHA-256 from the sidecar in the case record.
3. Transfer through an approved secure channel.
4. Verify the SHA-256 at the destination.
5. Preserve an original read-only copy.
6. Analyze a working copy where possible.
7. Restrict access according to the most sensitive information in the capsule.
8. Apply the organization's retention and deletion requirements.

## Chain-of-custody considerations

The module records case ID, operator, host, capsule ID, UTC timestamps, elevation state, collector status, and file hashes. These support traceability but do not prove identity or authenticity by themselves.

For formal custody requirements, also maintain an external record containing:

- who collected, received, copied, opened, and transferred the artifact;
- date/time and purpose of each action;
- storage location and access controls;
- source and destination checksums;
- tooling version and acquisition procedure;
- any deviation, warning, or failed source.

## Data sensitivity

Potentially sensitive sources include:

- process command lines;
- local and domain account identifiers;
- group memberships and privileges;
- network addresses, routes, shares, and DNS entries;
- Defender exclusions and security-policy settings;
- event-log messages;
- installed software/modules and driver inventory;
- scheduled-task actions and service binary paths.

Never upload a real capsule to a public issue, chat, paste service, or malware-analysis portal unless the evidence owner has explicitly approved that destination.

## Integrity limitations

SHA-256 detects modification when a trusted checksum or trusted manifest is available. It does not prevent an attacker with write access from replacing evidence and recalculating all hashes. Store the sidecar hash in a separate trusted case system or sign it using an organizational signing process when authenticity is required.

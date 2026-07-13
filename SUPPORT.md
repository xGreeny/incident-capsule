# Support

Use GitHub Issues for reproducible defects and narrowly scoped feature requests.

Before filing an issue:

1. run `Get-IncidentCapsuleProfile` to confirm the selected profile;
2. reproduce with the latest released version;
3. review `logs/collector.log` and `metadata/capsule.json`;
4. remove hostnames, usernames, IP addresses, domain names, case identifiers, and event content from any excerpt;
5. never attach a real capsule or EVTX file to a public issue.

Include the Windows edition/build, PowerShell version, module version, selected profile, elevation state, and the affected collector. A synthetic configuration or sanitized error message is preferable to a screenshot.

Operational incident-response advice and forensic interpretation are outside the issue tracker's scope. The repository supports the collection software itself.

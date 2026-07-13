# Security policy

## Supported versions

Security fixes are applied to the latest released major version.

| Version | Supported |
|---|---|
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Do not publish exploit details, collected evidence, hostnames, user identities, or capsule archives in a public issue.

Use **Security → Report a vulnerability** in the GitHub repository to open a private report. Include:

- the affected version and commit;
- the Windows and PowerShell versions;
- a minimal reproduction using synthetic data;
- the expected and observed behavior;
- security impact and any proposed mitigation.

When private vulnerability reporting is unavailable, open a public issue containing only a request for a private contact channel. Do not include technical details in that issue.

## Sensitive output

Incident Capsule is designed to collect security-relevant host data. A capsule can contain usernames, group memberships, process command lines, network addresses, event messages, security-policy settings, Defender exclusions, and other operationally sensitive material. Capsules must be handled as incident evidence, not as ordinary diagnostic attachments.

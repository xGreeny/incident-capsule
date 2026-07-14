# Changelog

All notable changes to Incident Capsule are documented in this file. The project follows [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-07-14

### Security

- Reject absolute, traversing, duplicate, alternate-data-stream, and reparse-point paths during manifest and archive verification.
- Inspect archive entry count, per-entry size, total expanded size, compression ratio, and symbolic-link metadata before extraction.
- Verify generated archives before `-RemoveWorkingDirectory` can remove the working evidence directory.
- Validate the conventional checksum list against the JSON manifest.

### Added

- External `.zip.verification.json` receipts for generated archives.
- Configurable bounded archive-verification limits.
- Spreadsheet-safe CSV exports while retaining JSON as canonical evidence.
- Adversarial integrity and archive test coverage.

### Changed

- Structured files are written through same-directory temporary files and atomically committed where supported.
- Runtime version and schema references are derived from the module manifest.
- CI dependencies are pinned to Pester 5.9.0 and PSScriptAnalyzer 1.25.0.
- Release packaging validates the packaged module before publication.

### Fixed

- Pester discovery under Windows PowerShell 5.1 and PowerShell 7.
- Invalid matrix expressions in the GitHub Actions workflow.
- Dependabot label assumptions for repositories without custom labels.

## [1.0.0] - 2026-07-12

### Added

- Local, read-only first-response collection for Windows endpoints and servers.
- Fifteen independent collectors covering system state, storage, processes, services, networking, sessions, local identities, scheduled tasks, persistence locations, Microsoft Defender, PowerShell, security configuration, hotfixes, drivers, and Windows event logs.
- Minimal, Standard, and Extended collection profiles.
- Offline HTML report with collection status, metrics, warnings, and evidence index.
- Structured JSON evidence envelopes and CSV exports for high-volume datasets.
- Curated EVTX export with configurable lookback and event limits.
- SHA-256 file manifest, conventional checksum list, archive sidecar checksum, and integrity-verification cmdlet.
- Graceful partial collection when individual cmdlets, channels, or privileges are unavailable.
- PowerShell 5.1 and PowerShell 7 compatible module layout.
- Pester tests, PSScriptAnalyzer integration, continuous integration, and tagged-release packaging.
- Security, evidence-handling, architecture, configuration, and collector-reference documentation.

[1.0.1]: https://github.com/xGreeny/incident-capsule/releases/tag/v1.0.1
[1.0.0]: https://github.com/xGreeny/incident-capsule/releases/tag/v1.0.0

# Changelog

All notable changes to Incident Capsule are documented in this file. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Unit tests for collector engine failure paths: terminating errors, missing result objects, out-of-root output files, and overall-status computation.
- Unit tests for offline report generation: empty collector results, HTML encoding of evidence-derived values, metric rendering, and unsafe evidence-link omission.

### Fixed

- `Get-ICOverallStatus` no longer fails on an empty collector result set, which previously masked the original error when acquisition failed before the first collector completed.
- A collector output file outside the capsule root is now recorded in `collector.log` in addition to the collector warnings.

### Documentation

- Aligned capsule directory and archive name examples with the actual naming scheme, which includes a random suffix.

## [1.1.0] - 2026-07-14

### Security

- Harden archive handoff with sidecar enforcement, checksum-list validation, symbolic-link metadata rejection, bounded safe extraction, and external `.zip.verification.json` receipts.
- Reject reparse points, absolute or traversing paths, alternate-data-stream separators, duplicate entries, and case-colliding paths before evidence access.

### Added

- `Test-IncidentCapsuleReadiness` with stable `Ready`, `ReadyWithWarnings`, and `Blocked` outcomes, effective configuration, privacy scope, resource limits, command/provider checks, event-channel availability, elevation context, destination writability, and storage headroom.
- Capsule, EVTX, native-command, native-output, and derived-timeline budgets with bounded built-in profile defaults and explicit skip/truncation reporting.
- Structured `metadata/coverage.json` with collector coverage, machine-readable issue codes, data-handling scope, and applied resource limits.
- Bounded, derived `analysis/timeline.json` and `analysis/timeline.csv` indexes with source-file and zero-based source-record provenance.
- Schema version 1.1 definitions for capsule metadata, collector envelopes, manifests, coverage, timelines, and verification receipts, while retaining compatible 1.0 inputs.

### Changed

- Finalization now records collection and finalization separately, writes metadata last, freezes the working directory before hashing, and fails closed when directory or archive verification does not pass.
- Native commands now have enforced time and output limits; CSV exports neutralize spreadsheet formulas; JSON, text, and CSV writes are atomic.
- Integrity verification now validates manifest structure, conventional checksum lists, paths, ZIP entry types, entry sizes, expanded size, and compression ratio before bounded extraction.
- `-RemoveWorkingDirectory` now removes the source directory only after the archive sidecar and embedded manifest both verify successfully.
- Offline reports now summarize coverage, limitations, privacy scope, resource limits, and the derived timeline without presenting a security verdict.
- Release packages are self-contained and smoke-tested through both Windows PowerShell 5.1 and PowerShell 7; tagged assets receive provenance attestations before an isolated least-privilege publish job.

### Fixed

- Empty derived timelines now finalize correctly under Windows PowerShell 5.1.
- Direct `powershell.exe -File build.ps1` execution and combined `-Task All` validation now work with the pinned toolchain.
- The packaged launcher now resolves its module from the extracted release instead of relying on a source checkout.

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

[1.1.0]: https://github.com/xGreeny/incident-capsule/releases/tag/v1.1.0
[1.0.1]: https://github.com/xGreeny/incident-capsule/releases/tag/v1.0.1
[1.0.0]: https://github.com/xGreeny/incident-capsule/releases/tag/v1.0.0

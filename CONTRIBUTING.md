# Contributing

Incident Capsule favors transparent, reviewable collection over broad but opaque acquisition. Contributions should preserve that design.

## Before opening a pull request

1. Create or reference an issue that describes the collection gap or defect.
2. Keep the collector local and read-only. A collector must not remediate, isolate, terminate, clear, quarantine, or reconfigure the system.
3. Use Windows-native APIs, CIM, documented PowerShell modules, or signed inbox utilities where practical.
4. Return structured objects. Text-only output is acceptable only for native utilities whose original representation carries evidentiary value.
5. Handle missing cmdlets, inaccessible providers, disabled event channels, and non-elevated execution without aborting the entire capsule.
6. Add Pester coverage for parsing, configuration, integrity, or collector behavior that can be tested safely.
7. Update the collector reference and changelog when behavior or output changes.

## Development setup

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser

./build.ps1 -Task Analyze
./build.ps1 -Task Test
```

A full local validation and release package can be produced with:

```powershell
./build.ps1 -Task All
```

## Collector contract

Every collector returns a result with these properties:

```text
OutputFiles  Paths written beneath the capsule root
Warnings     Recoverable limitations or unavailable evidence
Metrics      Small summary values used by the offline report
```

Collectors must write through the repository's evidence helpers so that files use the common schema envelope, UTF-8 encoding, predictable paths, and the final SHA-256 manifest.

## Pull-request checklist

- Pester passes in Windows PowerShell 5.1 and PowerShell 7.
- PSScriptAnalyzer reports no errors.
- No production evidence, customer identifiers, secrets, or real incident data is committed.
- New output is documented, bounded, and justified.
- Elevated and non-elevated behavior is considered.
- The change does not silently increase collection scope or privacy impact.

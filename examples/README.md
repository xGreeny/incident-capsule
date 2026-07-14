# Configuration examples

These PowerShell data files are imported with `Import-PowerShellDataFile`; they cannot execute commands.

- `config.standard.psd1` keeps the Standard collector set but extends event coverage to 48 hours.
- `config.privacy-conscious.psd1` declares a minimized data-handling scope and suppresses process command lines, Defender preferences, native EVTX export, and high-detail inventories.
- `config.extended.psd1` declares full data handling and enables explicit capsule, EVTX, command-output, and timeline budgets alongside executable hashing, signed-driver inventory, task XML, and a 72-hour event window.

Example:

```powershell
Invoke-IncidentCapsule `
    -OutputPath 'C:\IR\Cases' `
    -CaseId 'IR-2026-0042' `
    -Profile Standard `
    -ConfigurationPath .\examples\config.privacy-conscious.psd1
```

The selected profile is loaded first. Values in the data file then replace profile defaults. `-Collectors` and `-ExcludeCollector` are applied last.

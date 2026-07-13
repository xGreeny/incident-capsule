# Collector reference

All paths below are relative to the capsule root. JSON files use the common collector envelope unless noted otherwise.

## System

**Purpose:** establish the host, operating system, hardware, boot, clock, and execution context.

**Output:**

- `evidence/system/system.json`
- `evidence/system/time.json`
- `evidence/system/whoami.txt`

**Notes:** Secure Boot is not available on every firmware/platform combination. TPM and Windows Time data are collected when their interfaces exist.

## Storage

**Purpose:** describe disks, logical volumes, SMB shares, and encryption state.

**Output:**

- `evidence/storage/disks.json`
- `evidence/storage/volumes.json`
- `evidence/storage/shares.json`
- `evidence/storage/bitlocker.json`

**Notes:** BitLocker status can be partial without elevation. Share paths and labels can be sensitive.

## Processes

**Purpose:** preserve running-process metadata and parent relationships.

**Output:**

- `evidence/processes/processes.json`
- `evidence/processes/processes.csv`
- `evidence/processes/executable-hashes.json` when enabled
- `evidence/processes/executable-hashes.csv` when enabled

**Fields:** PID, PPID, image, executable path, optional command line, owner when available, session ID, creation time, and optional SHA-256/signature information.

**Notes:** Command lines can contain credentials or tokens. Disable them with `IncludeProcessCommandLines = $false`. Hashing is deduplicated and bounded by `MaximumExecutableHashes`.

## Services

**Purpose:** identify installed service persistence and current service state.

**Output:**

- `evidence/services/services.json`
- `evidence/services/services.csv`

**Fields:** name, display name, state, start mode, account, binary path, process ID, and exit codes.

## Network

**Purpose:** capture local network configuration and active endpoints without scanning remote systems.

**Output:**

- `evidence/network/adapters.json`
- `evidence/network/ip-addresses.json`
- `evidence/network/routes.json`
- `evidence/network/tcp-connections.json` and `.csv`
- `evidence/network/udp-endpoints.json` and `.csv`
- `evidence/network/dns-servers.json`
- `evidence/network/dns-cache.json`
- `evidence/network/neighbors.json`
- `evidence/network/ipconfig-all.txt`
- `evidence/network/route-print.txt`
- `evidence/network/arp-a.txt`
- `evidence/network/netstat-ano.txt`

**Notes:** Inbox command output is retained because it provides a stable fallback when NetTCPIP cmdlets are unavailable or restricted.

## Sessions

**Purpose:** record interactive sessions, logon-session metadata, and loaded user profiles.

**Output:**

- `evidence/sessions/logon-sessions.json`
- `evidence/sessions/loaded-profiles.json`
- `evidence/sessions/quser.txt`
- `evidence/sessions/qwinsta.txt`

**Notes:** Session-to-account correlation is intentionally conservative; the collector avoids broad association walks that can be slow on busy servers.

## LocalAccounts

**Purpose:** inventory the local security-account database and group memberships.

**Output:**

- `evidence/identities/local-users.json`
- `evidence/identities/local-groups.json`
- `evidence/identities/local-group-members.json`

**Notes:** The LocalAccounts module is not available in every host context and local accounts do not exist in the same form on domain controllers. CIM fallback preserves basic user/group inventory when possible.

## ScheduledTasks

**Purpose:** preserve task metadata, execution actions, triggers, principals, and runtime state.

**Output:**

- `evidence/scheduled-tasks/tasks.json`
- `evidence/scheduled-tasks/tasks.csv`
- `evidence/scheduled-tasks/xml/*.xml` when enabled

**Notes:** Protected task definitions can require elevation. XML filenames include a stable short digest to prevent path collisions.

## Persistence

**Purpose:** inspect a bounded set of common Windows autostart and permanent-subscription locations.

**Output:**

- `evidence/persistence/registry-autoruns.json`
- `evidence/persistence/ifeo-debuggers.json`
- `evidence/persistence/startup-files.json`
- `evidence/persistence/wmi-subscriptions.json` when enabled

**Coverage:** machine/current-user/loaded-user Run and RunOnce values, policy Run keys, Winlogon values, AppInit/AppCert values, IFEO Debugger values, startup folders, and WMI event filters/consumers/bindings.

**Notes:** This is not a complete autoruns implementation. Unloaded user hives are not mounted. The collector never loads a hive or executes a referenced file.

## Defender

**Purpose:** record Microsoft Defender platform posture and recent local detections.

**Output:**

- `evidence/defender/status.json`
- `evidence/defender/preferences.json` when enabled
- `evidence/defender/threat-detections.json`

**Notes:** Preferences can expose exclusions and operational paths. The collector reads but never changes Defender configuration.

## PowerShell

**Purpose:** establish available engines, execution policy, logging controls, module inventory, and profile metadata.

**Output:**

- `evidence/powershell/engines.json`
- `evidence/powershell/execution-policy.json`
- `evidence/powershell/logging-policy.json`
- `evidence/powershell/modules.json`
- `evidence/powershell/profiles.json`

**Notes:** Profile and PSReadLine history contents are not collected. Existing files are represented by path, size, time, and SHA-256 only.

## SecurityConfiguration

**Purpose:** preserve security controls that influence logging, access, and host exposure.

**Output:**

- `evidence/security/firewall-profiles.json`
- `evidence/security/firewall-rules.json`
- `evidence/security/audit-policy.txt`
- `evidence/security/local-security-policy.inf`
- `evidence/security/uac-rdp-lsa.json`
- `evidence/security/device-guard.json`
- `evidence/security/applocker-policy.xml` when available
- `evidence/security/netsh-firewall-profiles.txt`

**Notes:** The firewall-rule export is bounded and captures rule metadata, not every associated filter object. `secedit` and protected policy providers can require elevation.

## Hotfixes

**Purpose:** record installed QFE entries and recent Windows Update history.

**Output:**

- `evidence/hotfixes/qfe.json` and `.csv`
- `evidence/hotfixes/windows-update-history.json` and `.csv` when enabled

**Notes:** QFE inventory is not a complete statement of every package or servicing action. Windows Update history is bounded.

## Drivers

**Purpose:** capture service-driver state and optional signed PnP inventory.

**Output:**

- `evidence/drivers/system-drivers.json` and `.csv`
- `evidence/drivers/signed-pnp-drivers.json` and `.csv` when enabled
- `evidence/drivers/driverquery.csv`

**Notes:** Signed-driver inventory can be large and is bounded by `MaximumSignedDrivers`.

## EventLogs

**Purpose:** preserve a bounded decoded view for rapid analysis and native EVTX files for downstream tools.

**Output per channel:**

- `evidence/events/summaries/<channel>.json`
- `evidence/events/summaries/<channel>.csv`
- `evidence/events/evtx/<channel>.evtx` when enabled
- `evidence/events/channels.json`

**Decoded fields:** time, event ID, level, provider, machine, user SID, record ID, task, opcode, keywords, and message.

**Notes:** decoded messages can be locale-dependent and can contain sensitive data. EVTX export uses the profile's lookback query and does not clear or mutate the source channel.

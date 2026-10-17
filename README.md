# Sentinel Honeypot Lab

Internet-exposed Windows 11 honeypot in Azure, monitored with Microsoft Sentinel. Includes the lab configuration, KQL detection rules, hunting queries and triage notes produced from ~76 hours of real attack telemetry.

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Environment](#environment)
- [Exposure and containment](#exposure-and-containment)
- [Telemetry configuration](#telemetry-configuration)
- [Dataset](#dataset)
- [Detection rules](#detection-rules)
- [Rule backtests](#rule-backtests)
- [Findings](#findings)
- [Compromise assessment](#compromise-assessment)
- [Triage](#triage)
- [Repository layout](#repository-layout)
- [Reproducing the lab](#reproducing-the-lab)
- [Limitations](#limitations)
- [Cost](#cost)
- [Data handling](#data-handling)

## Overview

| | |
|---|---|
| Goal | Collect real Internet attack telemetry against an exposed Windows host, investigate it in Sentinel, and build tested detections |
| Platform | Azure, Microsoft Sentinel (Log Analytics), Azure Monitor Agent |
| Data source | Windows Security event log (`SecurityEvent` table) |
| Collection window | 2026-10-07 03:01 UTC to 2026-10-10 07:05 UTC (~76 h uptime, one short reboot on 2026-10-08 03:00 UTC) |
| Output | 7 KQL analytics rules (3 tested, 4 draft), 12 hunting queries, triage notes |
| Conclusion | No evidence of compromise in the collected telemetry |

## Architecture

```
Internet -> Public IP -> NSG -> Windows 11 VM (Defender and Windows Firewall disabled)
                                      |
                          Azure Monitor Agent (AMA)
                                      |
                          Data Collection Rule (DCR)
                                      |
                  Log Analytics workspace -> Microsoft Sentinel
                                             (analytics rules, workbook, incidents)
```

## Environment

| Component | Value |
|---|---|
| Region | Central India |
| VM size | Standard B2as v2 (2 vCPU, 8 GiB) |
| OS image | Windows 11 Pro 24H2 |
| OS disk | Standard SSD (StandardSSD_LRS), 127 GiB |
| Log agent | Azure Monitor Agent with a Data Collection Rule |
| SIEM | Microsoft Sentinel on a Log Analytics workspace |
| Subscription | Azure for Students |

## Exposure and containment

Exposure changed during the experiment.

| Phase | Inbound | Host | Outbound |
|---|---|---|---|
| Long run, start (2026-10-07, until ~03:28 UTC) | All ports | Defender and Windows Firewall off | Default (allow) |
| Long run, hardened (rest of run) | TCP 3389, TCP 445/135/139, ICMP | Defender and Windows Firewall off | Internet denied, AzureMonitor:443 allowed |

Final NSG rules:

| Direction | Priority | Name | Port | Protocol | Destination | Action |
|---|---|---|---|---|---|---|
| Inbound | 100 | RDP | 3389 | TCP | Any | Allow |
| Inbound | 110 | Allow-SMB-RPC-In | 445,135,139 | TCP | Any | Allow |
| Inbound | 120 | Allow-ICMP-In | * | ICMPv4 | Any | Allow |
| Outbound | 100 | Allow-AzureMonitor-Out | 443 | TCP | Service tag `AzureMonitor` | Allow |
| Outbound | 200 | Deny-Internet-Out | * | Any | Service tag `Internet` | Deny |

Containment controls:

- Outbound Internet denied so a compromised host cannot be used against third parties. Verified from the VM: `Test-NetConnection 8.8.8.8 -Port 443` failed, and `Heartbeat` continued to arrive.
- No other resources in the VNet. No personal accounts or data on the VM. Local admin password rotated at the start of the run (three `net user azureuser *` runs, 4724 x3 at 03:53 to 03:54 UTC).
- Account lockout policy: threshold 10 wrong passwords, ~10 min lockout. Inferred from the logs, not confirmed with `net accounts`: 14 lockouts correspond to exactly 140 wrong-password events on each of two accounts, and guessing against `azureuser` resumed ~10 min after its first lockout.
- Budget alert and defined teardown date.

## Telemetry configuration

Configuration applied on 2026-10-07 at ~03:09 UTC (the 4719 burst). Commands are in [`setup/setup_commands.md`](setup/setup_commands.md). Data before ~03:11 UTC on that day lacks command lines in 4688.

| Audit subcategory | Setting | Events used |
|---|---|---|
| Logon | Success, Failure | 4624, 4625 |
| Logoff | Success | 4634, 4647 |
| Account Lockout | Failure | 4740 |
| Special Logon | Success | 4672 |
| Credential Validation | Success, Failure | 4776 |
| User Account Management | Success, Failure | 4720, 4722, 4724 |
| Security Group Management | Success, Failure | 4732 |
| Process Creation | Success | 4688 |
| File Share / Detailed File Share | Success, Failure | 5140, 5145 |
| Other Object Access Events | Success, Failure | 4698, 4699, 4701, 4702 |
| Audit Policy Change | Success | 4719 |
| Security System Extension | Success | 4697 |

Additional settings:

| Setting | Value |
|---|---|
| Command line in 4688 | `ProcessCreationIncludeCmdLine_Enabled = 1` |
| Security log max size | 256 MB |
| PowerShell script block logging | Enabled (Event 4104, `Event` table) |
| Subcategory override | `SCENoApplyLegacyAuditPolicy = 1` |

Note: 4776 duplicates every failed network logon already recorded as 4625 (167,486 vs 167,477). Detections and counts use 4625 only.

## Dataset

Full run, 2026-10-07 03:01 UTC to 2026-10-10 07:05 UTC.

| Item | Count |
|---|---|
| Failed logons (4625) | 167,477 from ~70 distinct source IPs |
| NTLM credential validation (4776) | 167,486 |
| Successful logons (4624) | 1,878 |
| Logoffs (4634) | 1,208 |
| Special privileges assigned (4672) | 679 |
| Process creation (4688) | 3,960 |
| Account lockouts (4740) | 116 (azureuser 88, DefaultAccount 14, WDAGUtilityAccount 14) |
| Explicit-credential logons (4648) | 12 |
| Audit policy changes (4719) | 11 |
| Password reset attempts (4724) | 3 |
| Scheduled task created (4698) | 1 |
| Share access (5140, 5145) | 0 |
| Account created, group change, service install, log cleared (4720, 4722, 4732, 4697, 1102) | 0 |

Failed logons by period (6-hour buckets, UTC):

| Period | Window | 4625 count |
|---|---|---|
| Wave 1 | 2026-10-07 18:00 to 2026-10-08 06:00 | 77,223 |
| Wave 2 | 2026-10-09 18:00 to 2026-10-10 06:00 | 46,067 |
| All other buckets | rest of run | 44,187 |

Wave 1 is ~92% one source (144.76.103.122, 70,731 attempts). Wave 2 is multi-source.

## Detection rules

Rules 01-04 query `SecurityEvent` and count 4625 only (4776 duplicates every failure). Rule files are in [`rules/`](rules/).

| ID | Name | Logic | ATT&CK | Severity | Status |
|---|---|---|---|---|---|
| 01 | Password spray | Per source IP, 1 h: `DistinctUsers >= 20` and `Attempts >= 50` | T1110.003 | Medium | Tested |
| 02 | Valid account, wrong password | SubStatus `0xC000006A`, `>= 5` per IP and account per hour, joined to 4740 | T1110.001 | Medium, High if locked out | Tested |
| 03 | Anonymous NTLM network logon | 4624, Type 3, `ANONYMOUS LOGON`, external IP | T1135, T1021.002 | Low | Tested |
| 04 | High-volume failed logons | Per source IP, 1 h: `Attempts >= 200` (placeholder) | T1110 | Low | Draft |
| 05 | Audit policy changed | 4719 where subject is not a machine account | T1562.002 | Medium | Draft |
| 06 | Suspicious scheduled task | 4698 excluding `\Microsoft\` and OneDrive; alert on user-writable paths or script interpreters | T1053.005 | Medium | Draft |
| 07 | Account lockout | 4740 on a non-machine account; covers guessing spread below per-IP thresholds | T1110 | Medium | Draft |

Sentinel configuration for each rule:

| Setting | Value |
|---|---|
| Rule type | Scheduled query rule |
| Schedule / lookback | 30 min / 1 h (01, 02, 04, 07), 1 h / 1 h (03, 05, 06) |
| Entity mapping | `IpAddress` to IP; `TargetUserName` / `SubjectUserName` to Account |
| Incident grouping | One incident per matching IP (IP and account for rule 02, account for rule 07), 24 h grouping window |

Known false positives, used for tuning:

| Rule | False positive | Handling |
|---|---|---|
| 05 | Operator's own `auditpol` changes (burst of 4719) | Documented, confirmed against 4688 |
| 06 | `OneDrive Standalone Update Task`, created on first profile logon | Excluded by task name |

Rule 06 caveat: the task XML is XML-escaped inside `EventData`, so the `Command` extraction needs verification on a real 4698 before the rule is saved.

## Rule backtests

### Rule 01 (7 days, hourly)

| Source IP | Hour (UTC) | Attempts | Distinct users |
|---|---|---|---|
| 144.76.103.122 | 2026-10-07 23:00 | 12,027 | 5,031 |
| 144.76.103.122 | 2026-10-08 00:00 | 12,301 | 3,660 |
| 193.143.1.66 | 2026-10-08 20:00 | 69 | 25 |
| 193.143.1.66 | 2026-10-08 21:00 | 259 | 176 |
| 77.91.122.16 | 2026-10-09 18:00 | 19,868 | 828 |

Coverage gap 1: 144.76.103.122 produced 70,731 attempts, but rule 01 fired in only two hours. In the remaining hours it used fewer than 20 usernames. Rule 04 (volume per IP) addresses this and is not yet backtested.

### Rule 02 (full run, hourly, `>= 5` wrong passwords per IP and account)

| Source IP | Account | Hour (UTC) | Wrong passwords |
|---|---|---|---|
| 138.91.109.48 | AZUREUSER | 2026-10-07 07:00 | 14 |
| 138.91.109.48 | AZUREUSER | 2026-10-07 19:00 | 11 |
| 23.94.69.14 | azureuser | 2026-10-07 21:00 | 5 |
| 23.94.69.14 | azureuser | 2026-10-08 00:00 | 5 |
| 23.94.69.14 | azureuser | 2026-10-08 03:00 | 5 |
| 149.88.106.178 | azureuser | 2026-10-10 06:00 | 15 |
| 23.94.69.14 | guest | 2026-10-07 21:00, 2026-10-08 00:00 | 5 each |
| 103.160.232.131 | DefaultAccount, WDAGUtilityAccount | 2026-10-07 09:00 | 10 each |
| 103.250.146.103 | DefaultAccount, WDAGUtilityAccount | 2026-10-07 10:00 | 20 each |

Coverage gap 2: `azureuser` was locked out 88 times. At a threshold of 10 that implies ~880 wrong-password events, but only ~55 fall in hours caught by the table above. The rest was spread below the per-IP, per-hour threshold. Rule 07 (4740 on a non-machine account) covers it from the account side. Measured total: 970 wrong-password events (SubStatus `0xC000006A`) against `azureuser` from 11 source IPs, plus 1 event with no source address. Roughly 970 / 10 ≈ 97 lockout cycles, consistent with the 88 observed lockouts. Top source 23.94.69.14 with 466 attempts over about 3 days; three addresses in 149.88.106.0/24 (.173, .148, .178) contributed 303 combined, and two in 151.240.33.0/24 (.27, .13) contributed 45. Each address stays low-and-slow, so per-IP hourly thresholds miss most of it. Alerting on the lockout itself, or grouping by /24, catches it.

## Findings

| Finding | Evidence |
|---|---|
| Dictionary spray | 144.76.103.122: 70,731 attempts, 5,038 distinct usernames, 2026-10-07 21:10 to 2026-10-08 03:00 UTC. Last event 0.17 s before the shutdown event (1100); not seen again in the remaining ~52 h |
| Single-account brute force | 45.207.228.7: 13,446 attempts, 1 username (`administrator`, which does not exist) |
| High-rate burst | 77.91.122.16: 19,868 attempts, 828 usernames in 2 min 15 s (2026-10-09 18:37:08 to 18:39:24 UTC), ~147 attempts/s |
| Low-and-slow spray | 193.143.1.66: ~1 guess per username over two hours |
| Wave 2 is multi-source | At least six IPs, including 54.36.173.55 (11,987, one username), 163.121.35.2 (8,671, 6 usernames) and the 77.91.122.16 burst |
| Concentration | Top source accounts for 42% of all failures (144.76.103.122) |
| Valid username guessed | `azureuser`: 970 wrong-password events from 11 source IPs (top: 23.94.69.14 with 466; 149.88.106.0/24 with 303 combined), 88 lockouts |
| Built-in accounts targeted | DefaultAccount and WDAGUtilityAccount: 140 wrong-password events each (6 and 7 source IPs), 14 lockouts each. `guest`: 71 from one IP |
| Lockout containment | 116 lockouts, no successful named-account logon from any external IP. Lockouts also let attackers lock out the real admin |
| Anonymous NTLM probing | 1,192 anonymous logons from 10 IPs: 163.121.35.2 (1,167), 175.107.201.26 (16, periodic), 8 IPs with 1 to 2 each |
| Built-in admin renamed | SID `-500` belongs to `azureuser`; guesses at `administrator` returned `0xC0000064` (unknown user) |
| Username capitalisation | Different sources used different case (`AZUREUSER`, `azureuser`); KQL `by` groups are case-sensitive, so aggregate with `tolower()` |

Source IPs are reported as observed. No whois/ASN attribution was performed, and none is claimed. Geolocation (workbook map) reflects where an IP is registered, not where the operator is.

## Compromise assessment

| Question | Method | Result |
|---|---|---|
| Successful external named-account logon? | 4624, Types 3 and 10, non-local IP, grouped by source, full run | Only `ANONYMOUS LOGON` from scanner IPs, and the operator's own `azureuser` sessions |
| Did any high-volume attacker succeed? | 4624 from every IP with > 100 failures | Only `ANONYMOUS LOGON` (8 IPs, 1,190 logons) |
| Interactive logons by `azureuser` | 4624, Types 2, 7, 10, 11 | Four, all from the operator, 2026-10-07 03:07 to 03:54 UTC. None after |
| Operator sessions identified? | NLA pattern (two Type 3, then Type 10 or 7); logon ID matched to 4647; commands matched in 4688 | Four connections, 2026-10-07 03:07 to 03:54 UTC |
| Account / group / service changes? | 4720, 4722, 4732, 4697 | None |
| Log tampering? | 1102 | None |
| Audit policy changes? | 4719 | 11 events at 2026-10-07 03:09 UTC, operator's own `auditpol` run |
| Password changes? | 4724 | 3 events, 03:53 to 03:54 UTC, operator's `net user azureuser *` runs |
| Persistence via scheduled task? | 4698, 4701, 4699 | One created (OneDrive updater), one disabled (`VerifyWinRE`, built-in), one deleted (2026-10-08 03:26 UTC, `\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_OobeAppReady`, deleted by SYSTEM, consistent with the post-update activity). No suspicious tasks |
| Anonymous session activity? | 5140, 5145 | No share-access events recorded in the full run |
| Other | 5038 | One event, `DefenderSessionHelper.exe` in the Defender platform folder, at the first logon. Likely benign, not investigated further |

Conclusion: no evidence of a successful external named-account logon, persistence, or log tampering in the collected telemetry.

## Triage

Notes for each incident cluster are in [`triage/triage_notes.md`](triage/triage_notes.md).

| Activity | Verdict |
|---|---|
| Spray, 144.76.103.122 | True positive, no impact |
| High-rate burst, 77.91.122.16 | True positive, no impact (no logon of any kind from this IP) |
| Low-and-slow spray, 193.143.1.66 | True positive, no impact (no logon of any kind from this IP) |
| Targeted `azureuser` guessing and lockouts | True positive, no impact, contained by lockout policy |
| Guessing against DefaultAccount, WDAGUtilityAccount, guest | True positive, no impact |
| Anonymous NTLM probing | Low, reconnaissance |
| 4719 burst | Benign, operator action |
| 4698 OneDrive task, 4701 `VerifyWinRE` | Benign |
| Reboot, 2026-10-08 03:00 UTC | Benign, most likely a Windows Update restart |
| Operator sessions, 2026-10-07 03:07 to 03:54 UTC | Benign |

## Repository layout

```
README.md
rules/        KQL analytics rules 01-07
hunting/      investigation queries
setup/        audit policy, NSG and DCR configuration
triage/       triage notes and template
screenshots/  workbook and incident screenshots (redacted)
```

## Reproducing the lab

1. Create a resource group, VNet, NSG and a Windows 11 VM with a static Standard public IP.
2. Create a Log Analytics workspace, enable Microsoft Sentinel, and install Azure Monitor Agent with a DCR collecting Windows Security events.
3. Apply the audit policy and logging settings from [`setup/setup_commands.md`](setup/setup_commands.md).
4. Configure the NSG as in [Exposure and containment](#exposure-and-containment), then verify outbound denial and that `Heartbeat` still arrives.
5. Disable auto-shutdown and set a budget alert.
6. Create the rules from `rules/` as scheduled query rules with entity mapping and per-IP incident grouping.
7. Delete the VM, disk, NIC, public IP and NSG when finished. A deallocated VM still bills for its disk and public IP.

Run commands on the VM only after checking `hostname`.

## Limitations

- Windows Security events only. No Sysmon, NSG flow logs or packet capture.
- Windows Security events do not record the destination port, so the path of a given anonymous logon (RDP or SMB) is a hypothesis.
- Anonymous session activity is inferred from 4624/4634 and the absence of 5140/5145. Zero share events across 1,192 anonymous logons suggests these sessions never reached a share, but the logs cannot prove what they did.
- Lockout policy values are inferred from logs, not read from the host.
- Reboot at 2026-10-08 03:00 UTC: the operator's account logged off at 03:00:05 and Windows started at 03:00:33. Most likely an automatic Windows Update restart: from 02:45 UTC the Update Orchestrator (`UsoClient`, `MoUsoCoreWorker`) and servicing stack (`TrustedInstaller`, `TiWorker`) ran as SYSTEM, `MoNotificationUx` raised a `Reboot_Engaged` notification at 02:45:04, and `UpdateOrchestrator` tasks were rescheduled (4702). No `shutdown.exe`, interactive logon or external logon preceded it. Not confirmed from the System log (event 1074 is not collected). The dominant attacker of wave 1 stopped at the same moment.
- Single host, ~76 hours; traffic is opportunistic scanning.
- Defender and firewall disabled by design: malware and exploit attempts were not blocked and no AV telemetry exists.
- Sentinel Logs time range picker overrides `ago()` in queries; put an explicit `TimeGenerated` filter in every query.
- Pasted or exported result tables can lose rows; counts were cross-checked against totals where possible.

## Cost

October spend for the lab resource group as of 2026-10-10: ~INR 740 (VM ~321, OS disk ~315, public IP ~104, workspace 0). Sentinel was within the free trial.

## Data handling

Tenant ID, subscription ID, resource IDs and the operator's public IP are removed from screenshots and exports. Attacker IPs are included as the subject of the analysis.

# Triage notes

Drafts based on hunting results. **Update each one with the incident ID and timestamps once the incident is generated in Sentinel, and add whois/ASN after verifying.** Verdicts below are my reading of the data, not confirmed against a SOC process.

## Template

```
Incident:        <Sentinel incident ID / rule name>
Time (UTC):      <first - last>
Source:          <IP, ASN/country once verified>
What fired:      <rule + threshold>
What I checked:  <queries / event IDs>
Verdict:         <True positive (no impact) / Benign / False positive / Escalate>
Reasoning:       <2-3 lines>
Action:          <block at NSG / watchlist / tune rule / close>
```

## 1. Password spray - 144.76.103.122

- **What fired:** Rule 01. 12,027 and 12,301 attempts in two consecutive hours (Oct 7 23:00 and Oct 8 00:00 UTC), 5,031 and 3,660 distinct usernames.
- **Checked:** successful logons (4624) from this IP, any named-account success, post-compromise events.
- **Verdict:** True positive, no impact. Automated dictionary spray: 70,731 attempts across 5,038 usernames from 2026-10-07 21:10 to 2026-10-08 03:00 UTC. No successful logon from this IP. Activity stopped at the 03:00 UTC reboot (last event 0.17 s before the shutdown event) and was not seen again.
- **Action:** block at NSG, add to watchlist, add Rule 04 so lower-username-count hours of the same activity are also caught.

## 2. Password spray - 77.91.122.16 (short burst)

- **What fired:** Rule 01. 19,868 attempts, 828 distinct usernames, Oct 9 18:00 UTC hour. The activity lasted 2 min 15 s (a burst, not a sustained wave).
- **Checked:** logons of any kind (4624) from this IP: none.
- **Verdict:** True positive, no impact.
- **Action:** block, watchlist.

## 3. Low-and-slow spray - 193.143.1.66

- **What fired:** Rule 01. 69 attempts (25 usernames) then 259 attempts (176 usernames) in consecutive hours, Oct 8 20:00-21:00 UTC.
- **Reasoning:** close to one guess per username. A raw failed-logon count would never flag this, which is why the rule keys on distinct usernames.
- **Verdict:** True positive, no impact. No logon of any kind from this IP.
- **Action:** block, watchlist.

## 4. Targeted real username with lockouts - `azureuser` (11 source IPs)

- **What fired:** Rule 02, partly. 970 wrong-password events (SubStatus 0xC000006A) against `azureuser` from 11 source IPs. Top sources: 23.94.69.14 (466), three addresses in 149.88.106.0/24 (303 combined), 138.91.109.48 (54), two addresses in 151.240.33.0/24 (45 combined). 138.91.109.48 sent attempts every ~2 min 40 s starting Oct 7 06:56 UTC; after 10 wrong passwords the account locked out (07:21:51 UTC) and the next three attempts returned 0xC0000234 (locked out).
- **Checked:** successful logons for `azureuser` from these IPs (none), lockout events (4740): 88 for `azureuser`, 116 across all accounts.
- **Coverage gap:** most of this guessing stayed under the per-IP hourly threshold in Rule 02. Rule 07 (lockout on a non-machine account) catches it from the account side.
- **Verdict:** True positive, no impact. `azureuser` is the default Azure admin name and appears in common wordlists; the lockout policy (threshold 10, inferred from the logs) contained the guessing.
- **Action:** block the IPs, keep Rule 02 at High severity when Lockouts > 0, enable Rule 07.

## 5. Anonymous NTLM probing - 163.121.35.2 and others

- **What fired:** Rule 03. 163.121.35.2 produced 1,167 anonymous NTLM network logons; 175.107.201.26 produced 16 at a regular ~25-30 minute interval on day 1; several other IPs produced a single logon each.
- **Checked:** share-access events (5140/5145): none recorded in the inventoried window. Day 1: one session lasted ~141 ms with no evidence of authenticated access.
- **Verdict:** Benign-to-low. Automated SMB null-session reconnaissance; no evidence of access to shares.
- **Limitation:** Security logs cannot show what the session did beyond these events, and do not record the destination port.
- **Action:** watchlist, keep Rule 03 at Low severity.

## 6. Benign - audit policy changes (4719 burst)

- **What:** 11 4719 events by `azureuser` within ~1 s at 03:09 UTC on Oct 7.
- **Checked:** matches the operator's own `auditpol` hardening session (4688 `auditpol.exe` at the same moment, same RDP session).
- **Verdict:** Benign (administrator action). This is the false-positive case for Rule 05.

## 7. Benign - scheduled task creation (4698)

- **What:** `\OneDrive Standalone Update Task-<SID>` created at 03:10 UTC on Oct 7.
- **Checked:** process creation around the event: `explorer.exe` launched OneDrive, which launched its own updater; Edge WebView installer ran in the same minute. All Microsoft binaries in standard paths with expected parents.
- **Verdict:** Benign. OneDrive registers this task on the first profile logon. This is the false-positive case for Rule 06 and why it excludes `\Microsoft\` and OneDrive tasks.
- **Limitation:** the task's command and arguments were not extracted (empty), and no Sysmon file hashes were available.

## 8. Benign - unexpected reboot (2026-10-08 03:00 UTC)

- **What:** the operator account logged off at 03:00:05 and Windows started at 03:00:33.
- **Checked:** 4688 and 4698/4699/4702 from 02:45 to 03:40 UTC. The Update Orchestrator (`UsoClient`, `MoUsoCoreWorker`) and servicing stack (`TrustedInstaller`, `TiWorker`) ran as SYSTEM from 02:45; `MoNotificationUx` raised `Reboot_Engaged` at 02:45:04. No `shutdown.exe`, interactive logon or external logon preceded the restart. The task deleted at 03:26:14 (4699) was `\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_OobeAppReady`, deleted by SYSTEM.
- **Verdict:** Benign. Most likely an automatic Windows Update restart.
- **Limitation:** System log event 1074 (restart initiator) is not collected, so the initiator is inferred, not confirmed.
- **Lesson:** an unattended honeypot will restart itself; collect the System log or disable automatic restart in the next version.

## 9. Benign - operator sessions

- **What:** four `azureuser` sessions from one IP (the operator's ISP, confirmed by the operator): one Type 10 at 03:07 UTC on Oct 7, then three Type 7 reconnects, the last at 03:54 UTC. No interactive session afterwards.
- **Verdict:** Benign. This is the only interactive logon activity in the dataset.

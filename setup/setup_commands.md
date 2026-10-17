# Setup commands

Run in an elevated PowerShell **inside the VM**. Check `hostname` first so you do not run these on your own laptop.

## 1. Audit policy

```powershell
# Make advanced audit subcategories override legacy policy
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"Security State Change" /success:enable
```

## 2. Command-line logging, log size, PowerShell logging

```powershell
# Include command line in 4688 process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Security log to 256 MB
wevtutil sl Security /ms:268435456

# PowerShell script block logging (Event 4104)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

## 3. Verify

```powershell
auditpol /get /category:*
wevtutil gl Security | findstr maxSize
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
```

Then open a new PowerShell window, run `whoami`, and confirm a 4688 with a filled Command Line appears in Event Viewer.

## 4. NSG (Azure portal)

Final configuration:

| Direction | Priority | Name | Port | Protocol | Destination | Action |
|---|---|---|---|---|---|---|
| Inbound | 100 | RDP | 3389 | TCP | Any | Allow |
| Inbound | 110 | Allow-SMB-RPC-In | 445,135,139 | TCP | Any | Allow |
| Inbound | 120 | Allow-ICMP-In | * | ICMPv4 | Any | Allow |
| Outbound | 100 | Allow-AzureMonitor-Out | 443 | TCP | Service tag `AzureMonitor` | Allow |
| Outbound | 200 | Deny-Internet-Out | * | Any | Service tag `Internet` | Deny |

Verify containment from inside the VM (the source address must be the VM's private IP, not your laptop's):

```powershell
Test-NetConnection 8.8.8.8 -Port 443   # expect TcpTestSucceeded : False
```

Verify telemetry still flows after the outbound rule:

```kql
Heartbeat | where Computer startswith "CORP" | top 1 by TimeGenerated
```

## 5. Data Collection Rule

- Windows Security events via AMA (all Security events or a custom XPath that includes 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4719, 4720, 4732, 4740, 5140, 5145).
- Optional: add `Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]` (lands in the `Event` table, not `SecurityEvent`).

## 6. Lab hygiene

- Auto-shutdown disabled for the long run, static public IP, budget alert set before leaving the VM running.
- Unique password, no personal sign-ins on the VM.
- Teardown: delete the VM, OS disk, NIC, public IP and NSG individually. Keep the Log Analytics workspace if you still want to query the data. A deallocated VM still bills for its disk and IP.

# Incident Report — IR-001
**Classification:** Confidential (Lab Environment)  
**Report Date:** 2026-06-05  
**Analyst:** Rahul Yadav  
**Severity:** Critical  
**Status:** Detected and Documented  

---

## Executive Summary

A simulated brute force and credential dumping attack was conducted against a Windows 11 endpoint using Atomic Red Team on 5 June 2026. The attack was detected in real time by a Wazuh SIEM deployment using a combination of built-in and custom detection rules. A total of 1,263 security events were generated during the session, with 58 alerts at severity Level 12 or above, including a Level 15 critical alert triggered by Sysmon detecting attacker tooling being staged in the Temp directory.

The detection pipeline successfully identified multiple MITRE ATT&CK techniques across two independent data sources — Windows Security event logs and Sysmon endpoint telemetry — without any manual intervention.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Endpoint | Windows 11 ARM (Windows11Arm) — IP: 10.0.2.15 |
| Agent | Wazuh Agent v4.14.5 — Agent ID: 001 — Name: WindowsHost |
| SIEM | Wazuh Manager v4.14.5 on Ubuntu — IP: 192.168.29.168 |
| Telemetry | Sysmon (Microsoft-Windows-Sysmon/Operational) |
| Attack Tool | Atomic Red Team (Invoke-AtomicRedTeam) |

---

## Attack Timeline

| Time (IST) | Event |
|------------|-------|
| 13:00 | Wazuh manager restarted with clean custom rules loaded |
| 13:40 | Atomic Red Team `Invoke-AtomicTest T1003.001` executed on Windows 11 |
| 13:40:25 | **First Rule 92213 fires** — Sysmon EID 11 detects PowerShell dropping `.ps1` script to Temp folder |
| 13:45:10 | Rule 92213 fires again — second Atomic Red Team sub-technique executing |
| 13:46–14:41 | Multiple Level 12–15 alerts fire — process injection and suspicious svchost activity |
| 13:59:33 | **Peak alert activity** — Rule 92213 fired 20 times total during session |
| 14:00 | Authentication failure events (EID 4625) begin generating |
| 14:41 | Final alerts captured — total session 1,263 events |

---

## Detections

### Detection 1 — Ingress Tool Transfer (CRITICAL)

| Field | Value |
|-------|-------|
| Rule ID | 92213 |
| Severity | Level 15 — Critical |
| MITRE Technique | T1105 — Ingress Tool Transfer |
| MITRE Tactic | Command and Control |
| Data Source | Sysmon Event ID 11 (FileCreate) |
| Times Fired | 20 |
| First Seen | 2026-06-05 13:40:25 IST |

**What happened:** When Atomic Red Team executed, PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) automatically wrote temporary `.ps1` script files to `C:\Users\Windows11\AppData\Local\Temp\`. Sysmon Event ID 11 (File Create) logged this activity. Wazuh rule 92213 matched the Temp folder path as a location commonly used by malware for staging. The Sysmon rule name field explicitly tagged this as `technique_id=T1059.001,technique_name=PowerShell` confirming the technique.

**Raw Evidence:**
```
Alert: 1780647025.1564865
Time: 2026 Jun 05 13:40:25
Rule: 92213 (level 15) — Executable file dropped in folder commonly used by malware
Agent: WindowsHost (10.0.2.15)
Channel: Microsoft-Windows-Sysmon/Operational
EventID: 11
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\Windows11\AppData\Local\Temp\__PSScriptPolicyTest_31ycbrhv.sng.ps1
```

---

### Detection 2 — Process Injection Activity (HIGH)

| Field | Value |
|-------|-------|
| Rule ID | 92910 |
| Severity | Level 12 — High |
| MITRE Technique | T1055 — Process Injection |
| Data Source | Sysmon |
| Description | Explorer process accessed by OneDrive.exe — possible process injection |

**What happened:** Sysmon detected OneDrive.exe accessing the Explorer process memory — a behaviour associated with process injection techniques used by malware to hide execution inside legitimate processes.

---

### Detection 3 — Suspicious svchost Activity (HIGH)

| Field | Value |
|-------|-------|
| Rule ID | 61618 |
| Severity | Level 12 — High |
| Description | Sysmon — Suspicious Process — svchost.exe |
| Data Source | Sysmon |

**What happened:** Sysmon flagged svchost.exe behaviour consistent with malicious use — a common living-off-the-land technique where attackers abuse the legitimate Windows service host process.

---

### Detection 4 — Brute Force Authentication (HIGH)

| Field | Value |
|-------|-------|
| Rule ID | 100001 (custom) |
| Severity | Level 10 — High |
| MITRE Technique | T1110 — Brute Force |
| Data Source | Windows Security Event ID 4625 |
| Correlation Logic | 5+ failed logons within 60 seconds |

**What happened:** Multiple failed authentication attempts (Event ID 4625) were recorded against the local Windows account. Custom Wazuh correlation rule 100001 was written specifically to detect this pattern — 5 or more failures within a 60-second window triggers a Level 10 alert.

---

## Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
|----------|-------|---------|
| File path | `C:\Users\Windows11\AppData\Local\Temp\__PSScriptPolicyTest_*.ps1` | Atomic Red Team staging |
| Process | `powershell.exe` | Script execution engine |
| Process | `svchost.exe` | Suspicious behaviour flagged |
| Event ID | 4625 | Failed logon attempts |
| Event ID | 11 | Sysmon file creation in Temp |
| Event ID | 10 | LSASS memory access attempt |
| MITRE Tactic | Command and Control | Dominant tactic during session |

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Detected |
|---|---|---|---|
| T1105 | Ingress Tool Transfer | Command and Control | ✅ Rule 92213 |
| T1110 | Brute Force | Credential Access | ✅ Rule 100001 |
| T1055 | Process Injection | Defense Evasion / Privilege Escalation | ✅ Rule 92910 |
| T1059.001 | PowerShell | Execution | ✅ Sysmon tag |
| T1003.001 | LSASS Memory Dump | Credential Access | ✅ Simulated via ART |

---

## Dashboard Statistics

| Metric | Value |
|--------|-------|
| Total events | 1,263 |
| Alerts Level 12+ | 58 |
| Authentication failures | 13 |
| Authentication successes | 2 |
| Rule 92213 (Level 15) fires | 20 |
| MITRE tactics detected | 8+ |

---

## Findings and Gaps

**What worked well:**
- Sysmon provided immediate visibility into attacker tooling behaviour without any custom rules required
- MITRE ATT&CK mapping was automatic — techniques appeared in the dashboard without configuration
- The detection pipeline caught attack activity across multiple independent data sources simultaneously

**Gaps identified:**
- Custom rule 100001 requires tuning — `same_source_ip` logic does not correlate localhost-sourced brute force attempts due to missing source IP in EID 4625 when attacking loopback
- No active response was configured — the attacker IP was not automatically blocked
- Alert fatigue risk — 1,263 events generated; without tuning, high-volume background noise could mask real threats

---

## Recommendations

| Priority | Recommendation |
|----------|---------------|
| High | Enable account lockout policy — lock account after 5 failed attempts |
| High | Configure Wazuh active response to auto-block IPs triggering rule 100001 |
| High | Implement MFA on all local and domain accounts |
| Medium | Tune rule 100001 to handle loopback/internal source IPs correctly |
| Medium | Create alert suppression rules for known-good background noise (OneDrive, Windows Update) |
| Medium | Add PowerShell ScriptBlock logging to catch in-memory execution |
| Low | Deploy honeypot accounts to detect credential stuffing attempts earlier |
| Low | Schedule weekly rule review to identify new detection opportunities from alert data |

---

## Evidence

| File | Description |
|------|-------------|
| `evidence/screenshots/01_agent_active.png` | Wazuh dashboard showing WindowsHost agent active |
| `evidence/screenshots/02_custom_rules.png` | Custom rules loaded in nano editor |
| `evidence/screenshots/03_attack_execution.png` | Atomic Red Team T1003.001 executing on Windows 11 |
| `evidence/screenshots/04_level15_alert.png` | Level 15 critical alert detail — Rule 92213 |
| `evidence/screenshots/05_alert_list.png` | Full alert list sorted by severity |
| `evidence/screenshots/06_mitre_heatmap.png` | MITRE ATT&CK dashboard with detected techniques |
| `evidence/screenshots/07_timeline_spike.png` | Threat hunting dashboard showing attack spike |
| `evidence/alert_T1105.json` | Raw JSON alert from rule 92213 |

---

## Analyst Notes

This project was conducted entirely in a controlled lab environment using VirtualBox VMs. No real systems were targeted. All attack techniques were simulated using Atomic Red Team, an open-source adversary simulation framework maintained by Red Canary and mapped to MITRE ATT&CK.

The most significant finding was that Sysmon endpoint telemetry detected attacker tooling automatically at Level 15 severity before any custom rules were needed — demonstrating the value of deep endpoint visibility in a SOC environment.

---

**Report prepared by:** Rahul Yadav  
**Date:** 2026-06-05  
**Environment:** Home Lab (VirtualBox — macOS host)

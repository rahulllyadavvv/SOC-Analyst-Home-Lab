# Attack Simulation — Commands and Procedure

**Author:** Rahul Yadav  
**Date:** 2026-06-05  
**Platform:** Windows 11 ARM (Windows11Arm)  
**Tool:** Atomic Red Team (Invoke-AtomicRedTeam)

> All commands were executed in a controlled lab environment. No real systems were targeted.

---

## Prerequisites

### Atomic Red Team Installation (Windows PowerShell — Admin)

```powershell
# Set execution policy
Set-ExecutionPolicy Bypass -Scope CurrentUser

# Install Atomic Red Team framework
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Import the module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

---

## Attack 1 — Brute Force Password Guessing (T1110.001)

**MITRE Technique:** T1110.001 — Brute Force: Password Guessing  
**Objective:** Generate multiple failed Windows authentication events (EID 4625)  
**Expected Detection:** Wazuh Rule 100001 (Level 10)

```powershell
# View test details before running
Invoke-AtomicTest T1110.001 -ShowDetails

# Execute the test
Invoke-AtomicTest T1110.001
```

**Manual simulation (generates EID 4625 events):**
```powershell
for ($i=1; $i -le 6; $i++) {
    net use \\localhost\IPC$ /user:FakeUser WrongPass2025 2>$null
    Write-Host "Attempt $i"
    Start-Sleep -Milliseconds 400
}
```

**Events generated:** Windows Security EID 4625 (Failed Logon)  
**Alert fired:** Rule 92000 (built-in) → Rule 100001 (custom, Level 10)

---

## Attack 2 — Password Spraying (T1110.003)

**MITRE Technique:** T1110.003 — Brute Force: Password Spraying  
**Objective:** Attempt one password against multiple usernames  
**Expected Detection:** Wazuh Rule 100001 (Level 10)

```powershell
# View test details
Invoke-AtomicTest T1110.003 -ShowDetails

# Execute the test
Invoke-AtomicTest T1110.003
```

**Events generated:** Windows Security EID 4625  
**Alert fired:** Rule 92000 (built-in) → Rule 100001 (custom, Level 10)

---

## Attack 3 — LSASS Credential Dumping (T1003.001)

**MITRE Technique:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Objective:** Simulate credential theft from LSASS process memory  
**Expected Detection:** Wazuh Rules 92213 (Level 15), 100004 (Level 15)

```powershell
# View all sub-tests
Invoke-AtomicTest T1003.001 -ShowDetails

# Execute — this ran multiple sub-techniques:
# T1003.001-2: Dump LSASS using comsvcs.dll
# T1003.001-3: Direct system calls
# T1003.001-4: NanoDump
# T1003.001-6: Mimikatz offline credential theft
# T1003.001-7: pypykatz
# T1003.001-8: Out-Minidump.ps1
Invoke-AtomicTest T1003.001
```

**Events generated:**  
- Sysmon EID 11 — PowerShell dropping `.ps1` scripts to Temp folder  
- Sysmon EID 10 — LSASS memory access attempts  

**Alerts fired:**  
- Rule 92213 (Level 15) — Executable file dropped in Temp (T1105)  
- Rule 61618 (Level 12) — Suspicious svchost.exe activity  
- Rule 92910 (Level 12) — Process injection detected  

---

## Observations During Execution

- Atomic Red Team staged `.ps1` scripts in `C:\Users\Windows11\AppData\Local\Temp\` before execution — immediately detected by Sysmon EID 11 and Rule 92213 at Level 15
- Multiple T1003.001 sub-techniques failed with "system cannot find path specified" — indicating some prerequisites (Mimikatz binary, NanoDump) were not pre-staged, which is expected behaviour for a basic ART install
- Sub-techniques that did execute generated Sysmon process access events visible in Wazuh
- Total of 1,263 events captured across the full session

---

## Detection Summary

| Attack | Technique | Events Generated | Rules Triggered | Max Level |
|--------|-----------|-----------------|-----------------|-----------|
| Brute Force | T1110.001 | EID 4625 | 92000, 100001 | 10 |
| Password Spray | T1110.003 | EID 4625 | 92000, 100001 | 10 |
| LSASS Dump | T1003.001 | Sysmon EID 11, 10 | 92213, 92910, 61618 | 15 |

---

## Cleanup After Testing

```powershell
# Clean up Atomic Red Team test artifacts
Invoke-AtomicTest T1110.001 -Cleanup
Invoke-AtomicTest T1110.003 -Cleanup
Invoke-AtomicTest T1003.001 -Cleanup
```

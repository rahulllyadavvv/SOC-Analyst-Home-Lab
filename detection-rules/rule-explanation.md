# Custom Wazuh Rules — Line-by-Line Explanation

**Author:** Rahul Yadav  
**File:** `/var/ossec/etc/rules/local_rules.xml`

---

## How Wazuh Rules Work

Wazuh rules are written in XML and follow a layered model. Custom rules sit **on top of** built-in rules. Rather than re-detecting an event from scratch, a custom rule says "when this built-in rule has fired X times, then trigger me." This is called a **correlation rule** and is the core of SIEM detection logic.

---

## Rule 100001 — Brute Force Detection

```xml
<rule id="100001" level="10" frequency="5" timeframe="60">
  <if_matched_sid>92000</if_matched_sid>
  <description>Possible brute force: 5+ failed logons in 60 seconds</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>brute_force,authentication_failures</group>
</rule>
```

| Attribute/Tag | Value | Meaning |
|---|---|---|
| `id="100001"` | 100001 | Custom rules start at 100000+ to avoid conflict with built-in rules |
| `level="10"` | 10 | Severity level on a 0–15 scale. Level 10 = High. Triggers dashboard alerts |
| `frequency="5"` | 5 | This rule only fires after the child rule matches 5 times |
| `timeframe="60"` | 60 | Those 5 matches must happen within 60 seconds |
| `if_matched_sid` | 92000 | Stacks on built-in rule 92000 — Windows failed logon (EID 4625) |
| `mitre > id` | T1110 | Tags alert with MITRE ATT&CK Brute Force technique — appears in ATT&CK dashboard automatically |
| `group` | brute_force | Assigns to a group for filtering and dashboard building |

**Logic in plain English:** "If Windows reports 5 failed logins within 60 seconds, fire a Level 10 alert tagged as T1110 Brute Force."

---

## Rule 100002 — Successful Login After Brute Force

```xml
<rule id="100002" level="14">
  <if_sid>92000</if_sid>
  <field name="win.system.eventID">^4624$</field>
  <description>Successful logon after multiple failures - possible brute force success</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>brute_force,authentication_success</group>
</rule>
```

| Attribute/Tag | Value | Meaning |
|---|---|---|
| `level="14"` | 14 | Critical severity — higher than rule 100001 because a success after failures is worse than just failures |
| `if_sid` | 92000 | When rule 92000 (failed logon context) is active AND... |
| `field name="win.system.eventID"` | ^4624$ | ...a successful logon (EID 4624) is seen. `^` and `$` are regex anchors meaning exact match |

**Logic in plain English:** "If failed logon activity is happening AND then a successful login occurs, fire a Level 14 alert — the attacker may have gotten in."

---

## Rule 100003 — Mimikatz Execution

```xml
<rule id="100003" level="15">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.originalFileName">(?i)mimikatz</field>
  <description>Mimikatz execution detected - credential dumping attempt</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_dumping</group>
</rule>
```

| Attribute/Tag | Value | Meaning |
|---|---|---|
| `level="15"` | 15 | Maximum Wazuh severity. Mimikatz running anywhere is a P1 incident |
| `if_group>sysmon` | sysmon | Only applies to Sysmon log events — which contain richer process data |
| `originalFileName` | `(?i)mimikatz` | Checks the **PE header original filename**, not the running process name. `(?i)` = case-insensitive |

**Why `originalFileName` matters:** Attackers commonly rename `mimikatz.exe` to something innocent like `svchost.exe` or `update.exe`. But Windows embeds the original compiled name inside the binary's PE header. Sysmon reads and logs this field. So even a renamed mimikatz gets caught by this rule.

**Logic in plain English:** "If Sysmon sees any process whose original compiled filename contains 'mimikatz' (case-insensitive), fire maximum severity alert tagged T1003.001."

---

## Rule 100004 — LSASS Memory Access

```xml
<rule id="100004" level="15">
  <if_group>sysmon</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage">(?i)lsass.exe</field>
  <description>LSASS memory access detected - possible credential dumping</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_dumping</group>
</rule>
```

| Attribute/Tag | Value | Meaning |
|---|---|---|
| `if_group>sysmon` | sysmon | Sysmon events only |
| `eventID` | ^10$ | Sysmon Event ID 10 = ProcessAccess — fires when one process opens another's memory |
| `targetImage` | `(?i)lsass.exe` | The target of the memory access is lsass.exe — where Windows stores credential hashes |

**Why LSASS matters:** LSASS (Local Security Authority Subsystem Service) stores password hashes and Kerberos tickets in memory. Any tool reading LSASS memory — mimikatz, procdump, Task Manager dump — is attempting to steal credentials. This rule catches the behaviour regardless of which tool is used.

**Logic in plain English:** "If Sysmon sees any process reading the memory of lsass.exe, fire maximum severity alert tagged T1003.001."

---

## The Full Detection Chain

```
Atomic Red Team executes
        │
        ▼
Windows Event ID 4625 fires (failed logon)
        │
        ▼
Wazuh built-in Rule 92000 triggers (Level 5)
        │
        ▼  ← 5 times within 60 seconds
YOUR Rule 100001 fires (Level 10) — T1110 Brute Force
        │
        ▼  ← if a successful login then follows
YOUR Rule 100002 fires (Level 14) — Brute Force Success
        │
Sysmon Event ID 11 fires (file created in Temp)
        │
        ▼
Built-in Rule 92213 fires (Level 15) — T1105 Tool Staging
        │
Sysmon Event ID 10 fires (LSASS memory accessed)
        │
        ▼
YOUR Rule 100004 fires (Level 15) — T1003.001 Credential Dump
```

This chain tells the complete attacker story — from first failed login all the way to credential theft — visible as a timeline in the Wazuh Threat Hunting dashboard.

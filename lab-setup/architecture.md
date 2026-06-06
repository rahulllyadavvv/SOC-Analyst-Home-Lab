# Lab Setup and Architecture

**Author:** Rahul Yadav  
**Date:** 2026-06-05

---

## Environment Overview

| Component | Details |
|-----------|---------|
| Hypervisor | VirtualBox (macOS host) |
| VM 1 | Ubuntu Server — Wazuh Manager |
| VM 2 | Windows 11 ARM — Monitored Endpoint |
| Network | VirtualBox NAT + Host-Only Adapter |

---

## Network Configuration

```
macOS Host Machine
       │
       ├── Ubuntu VM  — IP: 192.168.29.168 (Wazuh Manager + Dashboard)
       │
       └── Windows VM — IP: 10.0.2.15     (Wazuh Agent + Sysmon)
                              ↕
                        TCP Port 1514 (agent communication)
                        TCP Port 443  (dashboard access)
                        TCP Port 9200 (OpenSearch)
```

---

## Wazuh Server Setup (Ubuntu)

### Installation

```bash
# Download and run Wazuh installer
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Verify all services running
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-indexer
```

### Verify Manager is Running

```bash
sudo /var/ossec/bin/agent_control -l    # List agents
sudo tail -f /var/ossec/logs/ossec.log  # Live logs
```

### Custom Rules Location

```
/var/ossec/etc/rules/local_rules.xml
```

After editing rules, always restart:
```bash
sudo systemctl restart wazuh-manager
```

---

## Wazuh Agent Setup (Windows 11)

### Installation

```powershell
# Download Wazuh agent MSI and install
# Configure server IP during installation: 192.168.29.168

# Verify agent is running
Get-Service WazuhSvc

# Check agent log for errors
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

### Agent Configuration File

`C:\Program Files (x86)\ossec-agent\ossec.conf`

Key sections configured:
- Server address: `192.168.29.168`
- Protocol: TCP port 1514
- Log channels: Application, Security, System, Sysmon/Operational

---

## Sysmon Setup (Windows 11)

Sysmon provides deep endpoint telemetry beyond standard Windows event logs. It captures process creation, network connections, file creation, and memory access events.

### Installation

```powershell
# Download Sysmon from Microsoft Sysinternals
# Download SwiftOnSecurity config for comprehensive coverage
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmon-config.xml"

# Install with config
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# Verify running
Get-Service Sysmon64
```

### Key Sysmon Event IDs Used in This Lab

| Event ID | Name | What It Captures |
|----------|------|-----------------|
| 1 | ProcessCreate | Every process that starts |
| 10 | ProcessAccess | One process reading another's memory (LSASS attacks) |
| 11 | FileCreate | Files written to disk (tool staging detection) |
| 3 | NetworkConnect | Outbound network connections |

### Add Sysmon Channel to Wazuh Agent

In `ossec.conf`, add:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Then restart the agent:
```powershell
Restart-Service WazuhSvc
```

---

## Verify Full Pipeline Working

### On Ubuntu — Check logs are arriving

```bash
# Check archives for any Windows events
sudo grep "WindowsHost" /var/ossec/logs/archives/archives.log | tail -5

# Watch alerts in real time
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### On Windows — Generate a test event

```powershell
# One failed login — should appear in Wazuh within seconds
net use \\localhost\IPC$ /user:TestUser WrongPassword 2>$null
```

If the event appears in `archives.log` — the full pipeline is working.

---

## Troubleshooting Reference

| Problem | Cause | Fix |
|---------|-------|-----|
| Agent shows Disconnected | Network/firewall blocking port 1514 | Check VirtualBox network adapter settings |
| No logs in archives.log | Missing localfile entries in ossec.conf | Add Security + Sysmon channels to agent config |
| Custom rules not firing | XML syntax error in local_rules.xml | Run `xmllint --noout local_rules.xml` |
| Wrong SID in if_matched_sid | Built-in rule IDs differ by Wazuh version | Check actual rule ID firing with `grep "4625" alerts.log` |
| Rule firing but wrong level | Duplicate rule ID in file | Search for rule ID and remove duplicate |

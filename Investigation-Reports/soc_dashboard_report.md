# 🔍 Lab Report — SOC Security Dashboard Built in Splunk

## Overview

| Field | Details |
|---|---|
| **Date** | 05 May 2026 |
| **Analyst** | Jimil Joshi |
| **Tool** | Splunk Enterprise — Classic Dashboard |
| **Dashboard Name** | SOC Security Dashboard |
| **Purpose** | Real time security monitoring for SOC L1 analysts |

---

## 1. Dashboard Description

A professional SOC Security Dashboard was built in Splunk Enterprise to provide real time visibility into all security events detected across the home lab. The dashboard consolidates all 13 previous lab investigations into a single monitoring view — exactly how a real SOC analyst monitors their environment.

---

## 2. Dashboard Components

### Row 1 — Security Metric Panels (Single Value):

| Panel | Query | Value |
|---|---|---|
| Failed Login Attempts | EventCode=4625 | 38 |
| New User Accounts Created | EventCode=4720 | 4 |
| Log Clearing Events | EventCode=1102 | 2 |
| Privilege Escalation Events | EventCode=4732 | 10 |

### Row 2 — More Security Metrics:

| Panel | Query | Value |
|---|---|---|
| Malicious Services Installed | EventCode=7045 | 12 |
| Account Lockouts | EventCode=4740 | 1 |
| PowerShell Events | EventCode=4104 | 679 |
| Process Creation Events | EventCode=4688 | 121,457 |

### Row 3 — Charts:

| Chart | Type | Shows |
|---|---|---|
| Failed Logins Over Time | Line Chart | Login failure trends — spike on Apr 27 |
| Top Suspicious Processes | Bar Chart | cmd.exe, net.exe, powershell.exe counts |

### Row 4 — Recent Events Table:

| Column | Description |
|---|---|
| _time | Timestamp of event |
| EventCode | Windows Event ID |
| Account_Name | Account involved |
| ComputerName | Machine name |

---

## 3. Dashboard Findings

### Key Observations:

**Failed Login Attempts — 38:**
- High number of failed logins detected over 30 days
- Spike visible on Apr 27 in line chart — brute force simulation

**Log Clearing — 2:**
- Critical alert — attacker attempted to destroy evidence
- Immediately visible on dashboard — SOC analyst would investigate

**PowerShell Events — 679:**
- Very high PowerShell activity — suspicious
- Includes recon commands and advanced attack techniques

**Process Creation — 121,457:**
- Full process monitoring active
- All suspicious processes tracked including cmd.exe and net.exe

**Recent Events Table:**
- Shows real time mix of EventCode 4625 and 1102
- Account `hp` and `JIMIL-JOSHI$` visible
- All from `JIMIL-JOSHI` machine

---

## 4. How SOC Analysts Use This Dashboard

Every morning a SOC analyst opens this dashboard and checks:

1. **Are failed logins spiking?** → Possible brute force
2. **Any new users created?** → Possible persistence
3. **Any log clearing?** → Attacker covering tracks — investigate immediately
4. **Any privilege escalation?** → Attacker gaining admin rights
5. **Any new services installed?** → Possible malware persistence
6. **PowerShell activity normal?** → Hunt for suspicious commands
7. **Any account lockouts?** → Active brute force in progress

---

## 5. Dashboard XML

The complete dashboard XML is saved in `Dashboards/soc_security_dashboard.xml` for reference and reproduction.

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/32_soc_dashboard_panels.png` | Full dashboard with 8 metric panels and charts |
| `screenshots/33_soc_dashboard_charts.png` | Charts and recent security events table |

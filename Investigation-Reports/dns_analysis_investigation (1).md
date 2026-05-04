# 🔍 Investigation Report — Suspicious DNS Query Detected

## Overview

| Field | Details |
|---|---|
| **Date** | 04 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Source** | Windows DNS Client Operational Log |
| **MITRE ATT&CK** | T1071.004 — DNS |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected **853 DNS query events** on host `JIMIL-JOSHI` between 15:07 and 15:22 on 04/05/2026. Among these, a suspicious DNS query for `suspicious-domain.xyz` was detected — consistent with malware C2 communication pattern.

In a real SOC environment, suspicious DNS queries are **High severity** because:
- Malware uses DNS to communicate with C2 servers
- Attackers use DNS tunneling to exfiltrate data
- Domain Generation Algorithms (DGA) create random domains for malware
- DNS traffic is often overlooked — making it perfect for attackers

---

## 2. Detection Queries Used

### Basic DNS Monitoring:
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-DNS-Client/Operational"
| rex field=_raw "(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
| stats count by domain
| sort -count
| head 20
```

### Suspicious Domain Hunting:
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-DNS-Client/Operational"
| search _raw="*xyz*" OR _raw="*\.ru*" OR _raw="*malware*" OR _raw="*suspicious*"
| table _time, _raw
| sort -_time
```

---

## 3. Findings

### Top Domains Queried:

| Domain | Count | Risk |
|---|---|---|
| watson.events.data.microsoft.com | 200 | ✅ Normal — Windows telemetry |
| dns.msftncsi.com | 84 | ✅ Normal — Windows connectivity check |
| quickdraw.splunk.com | 44 | ✅ Normal — Splunk updates |
| config.localhost | 26 | ✅ Normal — Local config |
| telemetry-splkmobile.dataeng.splunk.com | 26 | ✅ Normal — Splunk telemetry |
| google.com | 20 | ✅ Normal — User lookup |

### Suspicious Domain Detected:

| Time | Domain | Risk |
|---|---|---|
| 15:23:21 | `suspicious-domain.xyz` | 🔴 High — Suspicious TLD |

---

## 4. DNS Threat Analysis

### What is DNS C2 Communication?
When malware infects a machine it needs to communicate with the attacker's server. Instead of using HTTP (which is monitored), attackers use **DNS queries** because:
- DNS traffic is usually allowed through firewalls
- DNS is rarely monitored in detail
- Data can be hidden inside DNS query names

### Suspicious Indicators in DNS:

**Suspicious TLDs (.xyz, .ru, .tk, .pw):**
- `.xyz` domains are cheap and commonly used by attackers
- `.ru` domains are associated with cybercrime
- Legitimate businesses rarely use these TLDs

**Domain Generation Algorithm (DGA):**
- Malware generates random domain names automatically
- Example: `xkj29dks8f2.xyz`, `p9d2kls92.ru`
- Very long or random-looking domains are suspicious

**High Frequency Queries:**
- Malware queries same domain many times
- Used for data exfiltration via DNS tunneling
- Normal users rarely query same domain 200+ times

---

## 5. Timeline of Events

| Time | Event |
|---|---|
| 15:04:43 | DNS logging begins |
| 15:07:01 | High volume DNS activity starts |
| 15:23:21 | Suspicious domain `suspicious-domain.xyz` queried |
| 15:22:00 | DNS monitoring period ends |

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | DNS | T1071.004 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Reconnaissance | Active Scanning | T1595 |

---

## 7. Conclusion

Splunk successfully detected suspicious DNS activity including a query for `suspicious-domain.xyz`. DNS monitoring revealed both normal baseline traffic and suspicious domain lookups — demonstrating the importance of DNS log analysis in SOC operations.

**Verdict: True Positive — Suspicious DNS Query Detected ✅**

---

## 8. Recommendations

- Monitor DNS logs continuously in Splunk
- Alert on queries to suspicious TLDs (.xyz, .ru, .tk, .pw, .top)
- Hunt for DGA-like domains — long random looking names
- Alert on high frequency queries to same domain
- Use threat intelligence feeds to block known malicious domains
- Consider DNS sinkholes to redirect malicious domains
- Correlate DNS queries with network connections — confirm C2 communication

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/29_dns_raw_events.png` | Raw DNS Client Operational log events |
| `screenshots/30_dns_top_domains.png` | Top domains queried — baseline vs suspicious |
| `screenshots/31_dns_suspicious_domain.png` | Suspicious domain `suspicious-domain.xyz` detected |

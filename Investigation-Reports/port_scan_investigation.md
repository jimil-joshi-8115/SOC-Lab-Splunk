# 🔍 Investigation Report — Port Scan Detected

## Overview

| Field | Details |
|---|---|
| **Date** | 04 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Source** | Windows Firewall Log (pfirewall.log) |
| **MITRE ATT&CK** | T1046 — Network Service Discovery |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected **1,527 firewall events** from Windows Firewall logs on host `JIMIL-JOSHI` between 09:41 and 09:57 on 04/05/2026. Source IP `127.0.0.1` scanned ports 1 to 1024 in sequential order — a clear indicator of port scanning activity.

In a real SOC environment, port scanning is **High severity** because:
- Attackers scan ports to discover open services
- Open ports reveal running applications and potential vulnerabilities
- Port scanning is always the **first step** of an attack
- Identifies targets for exploitation

---

## 2. Detection Method

Windows Firewall logging was enabled and log file was added to Splunk as a monitored file source. SPL regex queries were used to extract fields from raw firewall log entries.

---

## 3. Detection Query Used

```spl
index=main sourcetype="firewall_log"
| rex field=_raw "(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src_ip>[\d.]+)\s+(?P<dst_ip>[\d.]+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)"
| stats count by dst_port, action
| sort -count
| head 20
```

---

## 4. Findings

### IP Statistics

| Source IP | Destination IP | Action | Count |
|---|---|---|---|
| 127.0.0.1 | 127.0.0.1 | ALLOW | 592 |
| 192.168.29.77 | 239.255.255.250 | DROP | 90 |
| 192.168.29.77 | 224.0.0.251 | DROP | 36 |

### Port Statistics

| Port | Action | Count | Meaning |
|---|---|---|---|
| 8089 | ALLOW | 618 | 🔴 Open — Splunk Management Port |
| 1900 | DROP | 100 | ✅ Closed — Blocked by Firewall |
| 5353 | ALLOW | 96 | 🔴 Open — DNS Service |
| 5353 | DROP | 55 | ✅ Partially Blocked |
| 9997 | ALLOW | 54 | 🔴 Open — Splunk Forwarder Port |
| 8000 | ALLOW | 32 | 🔴 Open — Splunk Web Port |

---

## 5. Port Scan Analysis

### ALLOW vs DROP Explained:

**ALLOW** = Windows Firewall permitted the connection
- Port is **OPEN** on the machine
- Service is **running** on this port
- Attacker **successfully discovered** this service

**DROP** = Windows Firewall blocked the connection
- Port is **CLOSED** on the machine
- No service running on this port
- Attacker's scan was **blocked**

### Port Scan Confirmed Because:
- ✅ Single source IP `127.0.0.1` hitting **multiple ports**
- ✅ **1,527 events** in just 15 minutes — very high volume
- ✅ **Mix of ALLOW and DROP** — scanner trying every port
- ✅ **Sequential pattern** — ports scanned in order 1 to 1024
- ✅ Multiple unique destination ports hit in short window

### What Attacker Discovered:
- Port **8089** open — Splunk Management API
- Port **8000** open — Splunk Web Interface
- Port **9997** open — Splunk Universal Forwarder
- Port **5353** open — DNS/mDNS Service

---

## 6. Timeline of Events

| Time | Event |
|---|---|
| 09:41:00 | Port scan begins — first firewall events detected |
| 09:41-09:57 | 1,527 connection attempts across ports 1-1024 |
| 09:57:00 | Port scan completes |
| After detection | Firewall logging disabled after lab |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Network Service Discovery | T1046 |
| Reconnaissance | Active Scanning | T1595 |
| Reconnaissance | Scanning IP Blocks | T1595.001 |

---

## 8. Conclusion

Splunk successfully detected the port scan by analyzing Windows Firewall logs. The SPL queries extracted source/destination IPs and ports, revealing a clear port scanning pattern with 1,527 connection attempts in 15 minutes from a single source IP.

**Verdict: True Positive — Port Scan Attack Detected ✅**

---

## 9. Recommendations

- Enable Windows Firewall logging permanently on all endpoints
- Add firewall log to Splunk for continuous monitoring
- Alert when single IP hits more than 10 unique ports in 1 minute
- Block scanning IPs at perimeter firewall immediately
- Investigate any ALLOW connections to sensitive ports (admin panels, databases)
- Use the following SPL to detect port scans automatically:

```spl
index=main sourcetype="firewall_log"
| rex field=_raw "(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src_ip>[\d.]+)\s+(?P<dst_ip>[\d.]+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)"
| stats dc(dst_port) as unique_ports, count by src_ip
| where unique_ports > 10
| sort -unique_ports
```

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/26_port_scan_raw_events.png` | Raw firewall log events in Splunk |
| `screenshots/27_port_scan_ip_stats.png` | IP statistics — source/destination with ALLOW/DROP counts |
| `screenshots/28_port_scan_ports.png` | Port statistics — which ports were open vs closed |

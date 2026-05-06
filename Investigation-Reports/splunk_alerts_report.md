# 🔍 Lab Report — Splunk Alerts Configured & Triggered

## Overview

| Field | Details |
|---|---|
| **Date** | 06 May 2026 |
| **Analyst** | Jimil Joshi |
| **Tool** | Splunk Enterprise — Alerts |
| **Total Alerts Created** | 5 |
| **Alerts Triggered** | 6 times |
| **Purpose** | Automated real time SOC alerting |

---

## 1. What Are Splunk Alerts?

Splunk Alerts automatically notify SOC analysts when suspicious activity is detected — without needing to manually run searches. When an alert triggers, it appears in the Triggered Alerts page and can also send emails or create tickets automatically.

---

## 2. Alerts Created

### Alert 1 — Brute Force Detection Alert

| Field | Value |
|---|---|
| **Title** | Brute Force Detection Alert |
| **Query** | `EventCode=4625` |
| **Type** | Scheduled — Every 1 minute |
| **Trigger** | Number of Results > 0 |
| **Severity** | 🟠 High |
| **Status** | ✅ Enabled |

---

### Alert 2 — Log Clearing Detected — Critical

| Field | Value |
|---|---|
| **Title** | Log Clearing Detected — Critical |
| **Query** | `EventCode=1102` |
| **Type** | Scheduled |
| **Trigger** | Number of Results > 0 |
| **Severity** | 🔴 Critical |
| **Status** | ✅ Enabled |

---

### Alert 3 — New User Account Created Alert

| Field | Value |
|---|---|
| **Title** | New User Account Created Alert |
| **Query** | `EventCode=4720` |
| **Type** | Scheduled |
| **Trigger** | Number of Results > 0 |
| **Severity** | 🟠 High |
| **Status** | ✅ Enabled |

---

### Alert 4 — Privilege Escalation Alert

| Field | Value |
|---|---|
| **Title** | Privilege Escalation Alert |
| **Query** | `EventCode=4732` |
| **Type** | Scheduled |
| **Trigger** | Number of Results > 0 |
| **Severity** | 🔴 Critical |
| **Status** | ✅ Enabled |

---

### Alert 5 — Malicious Service Installed Alert

| Field | Value |
|---|---|
| **Title** | Malicious Service Installed Alert |
| **Query** | `EventCode=7045` |
| **Type** | Scheduled |
| **Trigger** | Number of Results > 0 |
| **Severity** | 🔴 Critical |
| **Status** | ✅ Enabled |

---

## 3. Triggered Alerts

The Brute Force Detection Alert triggered **6 times** between 14:01 and 14:06 on 06/05/2026 after simulating failed login attempts.

| Time | Alert | Severity | Type |
|---|---|---|---|
| 14:06:17 | Brute Force Detection Alert | 🟠 High | Scheduled |
| 14:05:25 | Brute Force Detection Alert | 🟠 High | Scheduled |
| 14:04:05 | Brute Force Detection Alert | 🟠 High | Scheduled |
| 14:03:05 | Brute Force Detection Alert | 🟠 High | Scheduled |
| 14:02:07 | Brute Force Detection Alert | 🟠 High | Scheduled |
| 14:01:04 | Brute Force Detection Alert | 🟠 High | Scheduled |

---

## 4. How SOC Analysts Use Alerts

In a real SOC environment alerts are the **first line of notification:**

1. Attacker starts brute force → Alert triggers in seconds
2. SOC analyst gets notified → Opens Triggered Alerts
3. Clicks **View Results** → Sees exact events
4. Investigates → Opens investigation report
5. Responds → Blocks IP or locks account

**Without alerts** — SOC analyst would have to manually check dashboards every few minutes. **With alerts** — they are notified automatically! 🚀

---

## 5. Alert Best Practices

- Set appropriate severity levels — Critical for log clearing, High for brute force
- Use throttling to avoid alert fatigue — don't trigger same alert 100 times
- Always add **Add to Triggered Alerts** action — creates audit trail
- In production — also add **Email** or **Webhook** action for immediate notification
- Review and tune alerts regularly — reduce false positives

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/36_splunk_alerts_list.png` | All 5 alerts configured and enabled |
| `screenshots/37_splunk_triggered_alerts.png` | 6 triggered alerts showing in Activity |

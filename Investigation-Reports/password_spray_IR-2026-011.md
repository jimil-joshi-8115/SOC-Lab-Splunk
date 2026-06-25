# Investigation Report — Scenario 10: Password Spray

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-011 |
| **Scenario** | Password Spray |
| **Date of Simulation** | 25 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 High |
| **MITRE ATT&CK Technique** | T1110.003 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4625) |

---

## Scenario Description

This scenario simulates a **password spray attack** — a credential access technique in which an attacker attempts a small number of password guesses across **many different accounts**, rather than many guesses against a single account (brute force, as detected in Lab 01). This approach is specifically designed to evade account lockout policies, which typically trigger only after several consecutive failures *on the same account*. By spreading attempts across multiple accounts, an attacker can stay under each individual account's lockout threshold while still covering many possible targets.

**Simulated attack narrative:**
1. Attacker attempts authentication against four different account names (`hp1`, `hp2`, `administrator`, `guest`) using `runas`, each with an incorrect password.
2. All four attempts occur within a single, tight time window (~68 seconds), consistent with automated or scripted spray tooling rather than manual login attempts.

---

## Investigation Steps

1. Queried Event ID 4625 (Failed Logon) and grouped events into 2-minute time buckets.
2. Calculated the distinct count of targeted account names per time bucket to identify spray-pattern clustering.
3. Filtered for buckets with 3 or more distinct accounts targeted — the working threshold used to distinguish spray behavior from incidental, unrelated failures.
4. Reviewed raw failed logon events for the four simulated target accounts individually.
5. Investigated why an initial query (grouping by `Caller_Computer_Name`) returned no results, and identified the cause.

---

## Findings

| Time | Targeted Accounts | Failed Attempts | Significance |
|---|---|---|---|
| 2026-06-25 19:24:00 (bucket) | administrator, guest, hp, hp1, hp2 | 4 | Password spray pattern — 5 distinct account values across 4 failed logon events within ~68 seconds |

**Individual event detail:**

| Time | Account Targeted | Failure Reason |
|---|---|---|
| 19:24:05.836 | hp1 | Unknown user name or bad password |
| 19:24:14.607 | hp2 | Unknown user name or bad password |
| 19:24:27.353 | administrator | Unknown user name or bad password |
| 19:25:13.297 | guest | Unknown user name or bad password |

**Field behavior observation:** The `Caller_Computer_Name` field was empty across all four events, since the `runas` attempts were issued locally rather than over a network logon. An initial detection query grouped by `Caller_Computer_Name` and returned zero results as a consequence — this is a query design issue, not a logging gap. The corrected query grouped only by time bucket and account count, which successfully surfaced the pattern. Additionally, the `Account_Name` field returned both the subject (caller) account `hp` and the four target accounts together as a multivalue field in the aggregated view, which is expected Windows Security Log behavior for this event type and should be accounted for when interpreting distinct-account counts.

---

## Attack Timeline

```
19:24:05  →  Failed logon attempt — hp1
19:24:14  →  Failed logon attempt — hp2
19:24:27  →  Failed logon attempt — administrator
19:25:13  →  Failed logon attempt — guest
```

All four attempts occurred within approximately 68 seconds, well inside a single 2-minute detection window.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1110.003 | Brute Force: Password Spraying | Credential Access |

---

## Verdict & Analysis

This simulation successfully demonstrates detection of password spraying — a technique that is intentionally designed to evade naive brute-force detection logic. A detection rule built purely on "many failures against one account" (as used in Lab 01) would **not** catch this pattern, since each individual account here only received a single failed attempt. The distinguishing signal is instead the **distinct account count within a short time window**, which is the correct detection logic for this technique and a meaningfully different approach from standard brute-force detection.

This scenario provides a useful direct contrast to Lab 01 (Brute Force Detection) earlier in this repository: both rely on Event ID 4625, but the detection logic must be inverted — brute force groups by account and counts failures; password spray groups by time window and counts distinct accounts. Recognizing which grouping logic applies to which technique is a core SOC analytical skill.

**Verdict:** 🟠 Confirmed simulated password spray attack — multiple distinct accounts targeted within a single short time window, successfully detected via Windows native failed-logon logging.

---

## Response Actions

**Immediate:**
- Identify the source of the `runas` attempts and confirm whether the `hp` account or session was authorized to perform them.
- Review whether any of the targeted accounts (`administrator`, `guest`, `hp1`, `hp2`) exist as real, valid accounts on this or other hosts in the environment — and if so, verify they were not actually compromised.
- Check for any successful logons immediately following the failed spray attempts, which would indicate a successful guess.

**Recommended:**
- Build a correlation rule alerting when 3 or more distinct accounts experience failed logons within a 2–5 minute window from the same source.
- Implement account lockout policies that account for spray patterns specifically (e.g., organization-wide failed-logon-rate thresholds), not just per-account lockout counters.
- Enable monitoring for `Caller_Computer_Name`/source IP enrichment on all logon events where feasible, to support source-based correlation in addition to time-window-based correlation.
- Cross-reference any detected spray activity against the organization's known service accounts and shared/generic account names (`administrator`, `guest`), which are common spray targets.

---

## Conclusion

Scenario 10 demonstrates detection of password spraying — a credential access technique specifically designed to evade traditional brute-force detection — using native Windows Event ID 4625 logging in Splunk. This investigation completes the 10-scenario simulated attack campaign, and directly reinforces a lesson first introduced in Lab 01: that the same Event ID can require entirely different detection logic depending on the underlying attacker technique, reflecting the analytical depth expected of a SOC L1 analyst beyond simple keyword or event-ID matching.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final

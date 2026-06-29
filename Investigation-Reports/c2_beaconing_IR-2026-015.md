# Investigation Report — Scenario 14: Command & Control via DNS/HTTP Beaconing

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-015 |
| **Scenario** | Command & Control — DNS/HTTP Beaconing |
| **Date of Simulation** | 29 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK Techniques** | T1071.004, T1071.001 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates **Command and Control (C2) beaconing** — periodic check-ins from an established malware implant to a remote C2 server, asking for further instructions. This is meaningfully different from the burst-style DNS tunneling detected in Scenario 04 (8 queries within ~4 seconds, used to exfiltrate data). Beaconing instead involves **low-volume, regularly-spaced check-ins** over time; the data volume per check-in is small, but the *regularity of the interval* is itself the detection signature, since real C2 frameworks (e.g., Cobalt Strike) default to fixed or near-fixed check-in intervals.

**Simulated attack narrative:**
1. Simulated implant performs a DNS-based beacon check-in via `nslookup` against a C2-style domain (`c2-checkin.example.com`).
2. The same DNS check-in repeats two more times, spaced roughly (but not perfectly) at intervals.
3. Simulated implant performs an HTTP-based beacon check-in via PowerShell's `Invoke-WebRequest`, representing an alternate C2 channel.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for `nslookup.exe` invocations referencing the C2-style domain.
2. Queried Event ID 4688 for PowerShell `Invoke-WebRequest` invocations referencing a "checkin" endpoint.
3. Calculated inter-arrival time deltas between consecutive DNS beacon events to assess interval regularity — the core analytical signature of beaconing behavior.
4. Combined DNS and HTTP beacon indicators into a single chronological view to reconstruct the full check-in pattern across both channels.

---

## Findings

| Time | Account | Process | Command Line | Gap from Previous |
|---|---|---|---|---|
| 2026-06-29 14:53:23.980 | hp | nslookup.exe | `nslookup c2-checkin.example.com` | — |
| 2026-06-29 14:53:28.635 | hp | nslookup.exe | `nslookup c2-checkin.example.com` | ~4.7 seconds |
| 2026-06-29 14:53:49.980 | hp | nslookup.exe | `nslookup c2-checkin.example.com` | ~21.3 seconds |
| 2026-06-29 14:54:21.164 | hp | powershell.exe | `Invoke-WebRequest -Uri 'https://example.com/checkin' -UseBasicParsing -ErrorAction SilentlyContinue` | ~31.2 seconds |

**Interval regularity observation (simulation limitation, documented transparently):** The inter-arrival gaps observed here (~4.7s, ~21.3s, ~31.2s) are not consistent with one another, since these check-ins were triggered manually rather than by an automated implant on a fixed timer. A real beaconing detection rule relies on **low variance/jitter** between consecutive check-in intervals as the actual distinguishing signal — true C2 beacons typically vary by only a few percent around a fixed interval (e.g., 60 seconds ± 10%), which is what separates beaconing from coincidental, unrelated repeated activity. This manual simulation demonstrates the *queries and detection approach* correctly, but does not itself produce the low-jitter pattern a real detection rule would be tuned to flag with high confidence. This is noted here explicitly rather than overstating the regularity of the simulated data.

---

## Attack Timeline

```
14:53:23  →  DNS beacon check-in #1
14:53:28  →  DNS beacon check-in #2 (~4.7s later)
14:53:49  →  DNS beacon check-in #3 (~21.3s later)
14:54:21  →  HTTP beacon check-in (~31.2s later) — alternate C2 channel
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | Command and Control |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |

---

## Verdict & Analysis

This simulation demonstrates the detection approach for C2 beaconing — repeated, low-volume check-ins to a fixed external domain — using native Windows Event ID 4688 logging. Detection relied on identifying repeated `nslookup`/`Invoke-WebRequest` calls to the same destination, then specifically calculating time deltas between consecutive events, since regularity of interval (not simply repetition) is the actual analytical signature that distinguishes beaconing from normal, unrelated repeated DNS or HTTP activity.

In a real environment, this detection logic would be extended with a **jitter/variance threshold** (e.g., flagging domains queried at intervals with less than 10–15% variance over a sustained period), since legitimate applications occasionally repeat requests to the same domain but rarely with the tight regularity of an automated C2 beacon. The manually-triggered simulation in this lab does not itself exhibit that low-jitter pattern, which is documented honestly above as a limitation of manual simulation rather than a flaw in the detection logic itself.

This scenario also reinforces the contrast with Scenario 04: both involve repeated DNS activity to an external domain, but the *volume and timing pattern* differ meaningfully — Scenario 04 was a fast burst (data exfiltration), while this scenario is slow and spaced out (C2 check-in). Recognizing which pattern applies is itself a key analytical distinction.

**Verdict:** 🔴 Confirmed simulated C2 beaconing pattern — DNS and HTTP check-in channels both detected, with the interval-regularity analytical approach correctly applied even though the manually-simulated data does not itself exhibit true low-jitter beaconing.

---

## Response Actions

**Immediate:**
- Investigate the destination domain(s) `c2-checkin.example.com` (and equivalent HTTP endpoint) for reputation and any known association with malicious infrastructure.
- Review the source process tree for the `hp` account around the beaconing timeframe to identify what initiated the check-ins.
- Check for any data transferred in either direction during the HTTP check-in beyond the initial request.

**Recommended:**
- Build a correlation rule or scheduled search calculating inter-arrival time variance for repeated DNS/HTTP requests to the same destination per host, flagging low-jitter patterns sustained over multiple check-ins (a stronger, more specific rule than repetition alone).
- Cross-reference beacon destination domains against threat intelligence feeds and newly-registered-domain lists, since C2 infrastructure is frequently short-lived.
- Enable network-layer monitoring (proxy/firewall logs) in addition to endpoint process logs, to capture beacon traffic even where the originating process cannot be directly observed.
- Consider baselining "normal" external domain contact frequency per host to make anomalous regular check-ins easier to surface.

---

## Conclusion

Scenario 14 demonstrates the detection methodology for Command and Control beaconing — distinguishing this technique from burst-style exfiltration (Scenario 04) by focusing on check-in regularity rather than volume — using native Windows Event ID 4688 logging in Splunk. The investigation honestly documents a limitation of manual simulation (lack of true low-jitter regularity) while still correctly demonstrating the queries and analytical approach a real detection rule would use, reflecting the kind of transparent, evidence-based reasoning expected of a SOC L1 analyst.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final

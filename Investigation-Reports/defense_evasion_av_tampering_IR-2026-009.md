# Investigation Report — Scenario 08: Defense Evasion — AV/Firewall Tampering

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-009 |
| **Scenario** | Defense Evasion — AV/Security Tampering |
| **Date of Simulation** | 23 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK Technique** | T1562.001 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates an attacker attempting to **impair host security controls** before deploying further payloads — a defense evasion technique used to reduce the chance of detection, blocking, or remediation by security tooling. Two distinct controls were targeted: Windows Defender's real-time protection and the Windows Firewall (all profiles).

**Simulated attack narrative:**
1. Attacker disables Windows Defender real-time monitoring via PowerShell (`Set-MpPreference -DisableRealtimeMonitoring $true`).
2. Attacker disables the Windows Firewall across all profiles via `netsh advfirewall set allprofiles state off`.
3. (Post-simulation) Both controls are re-enabled as part of lab cleanup and to verify the remediation commands function correctly.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for PowerShell invocations of `Set-MpPreference` with `DisableRealtimeMonitoring`.
2. Queried Event ID 4688 for `netsh.exe` invocations targeting `advfirewall` with `state off`.
3. Queried for the corresponding re-enablement commands (`$false` / `state on`) to confirm cleanup was performed correctly.
4. Combined all four events into a single chronological view to reconstruct the full disable-then-restore lifecycle.
5. Checked for any Windows Defender Tamper Protection block or error in response to the `Set-MpPreference` command — none was observed.

---

## Findings

| Time | Account | Command Line | Significance |
|---|---|---|---|
| 2026-06-23 09:21:55.964 | hp | `powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"` | Windows Defender real-time protection disabled |
| 2026-06-23 09:22:08.865 | hp | `netsh advfirewall set allprofiles state off` | Windows Firewall disabled (all profiles) |
| 2026-06-23 09:22:26.476 | hp | `powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $false"` | Windows Defender real-time protection re-enabled (cleanup) |
| 2026-06-23 09:22:41.597 | hp | `netsh advfirewall set allprofiles state on` | Windows Firewall re-enabled (cleanup) |

**Tamper Protection observation:** The `Set-MpPreference -DisableRealtimeMonitoring $true` command executed successfully with no error or block returned. On a properly hardened endpoint, Windows Defender Tamper Protection would normally prevent this command from succeeding, even when run with administrative privileges, and would generate a distinct Defender-related event. The absence of any blocking behavior here indicates Tamper Protection is either disabled or not enforced on this host — this is flagged as a security gap in its own right, separate from the simulated attacker action itself.

---

## Attack Timeline

```
09:21:55  →  Windows Defender real-time protection disabled
09:22:08  →  Windows Firewall disabled (all profiles)
09:22:26  →  Windows Defender real-time protection re-enabled (cleanup)
09:22:41  →  Windows Firewall re-enabled (cleanup)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |

---

## Verdict & Analysis

This simulation successfully demonstrates detection of a foundational defense evasion technique — disabling host-based security controls before further malicious activity. Detection relied entirely on Event ID 4688 (Process Creation), filtering on `Set-MpPreference -DisableRealtimeMonitoring` and `netsh advfirewall ... state off` command-line patterns. Both are high-fidelity indicators, since legitimate business use of these exact commands outside of approved IT/security administration is rare and should always be investigated.

The most significant finding in this investigation is not the simulated command itself, but the **absence of Tamper Protection enforcement** on the host. In a properly configured enterprise environment, this exact command would be expected to fail, and that failure (or the attempt itself) would generate additional telemetry. The fact that it succeeded unimpeded represents a real security gap that would warrant a hardening recommendation independent of this specific simulated incident.

**Verdict:** 🔴 Confirmed simulated defense evasion — both AV and firewall tampering successfully detected, with a notable configuration gap (no Tamper Protection enforcement) identified as a secondary finding.

---

## Response Actions

**Immediate:**
- Verify current status of Windows Defender real-time protection and Windows Firewall on the affected host; confirm both are active.
- Investigate why `Set-MpPreference -DisableRealtimeMonitoring $true` was not blocked by Tamper Protection.
- Review for any malicious activity that may have occurred during the window security controls were disabled (09:21:55–09:22:26 for Defender; 09:22:08–09:22:41 for Firewall).

**Recommended:**
- Enable Windows Defender Tamper Protection across all endpoints to prevent unauthorized modification of security settings, even by accounts with local admin rights.
- Build a correlation rule alerting on any `Set-MpPreference` command containing `DisableRealtimeMonitoring $true`, or any `netsh advfirewall ... state off` command, treating both as high-severity alerts regardless of source account.
- Alert specifically on the *absence* of an expected block/error event following a tamper attempt, as this indicates a control gap rather than a successful defense.
- Periodically audit Tamper Protection and security control status across the environment as part of routine hardening checks.

---

## Conclusion

Scenario 08 demonstrates detection of host-based defense evasion — specifically AV and firewall tampering — using native Windows Event ID 4688 logging in Splunk. Beyond detecting the simulated attacker action, the investigation surfaced a meaningful secondary finding: the host's lack of Tamper Protection enforcement, which would allow this exact technique to succeed in a real attack. This reflects the kind of broader security-posture awareness expected of a SOC L1 analyst, beyond simply confirming that a query returns a match.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final

# Investigation Report — Scenario 09: Credential Dumping (LSASS Memory)

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-010 |
| **Scenario** | Credential Dumping — LSASS Memory |
| **Date of Simulation** | 24 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK Technique** | T1003.001 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates an attacker who has escalated privileges attempting to harvest credentials cached in memory by targeting `lsass.exe` (Local Security Authority Subsystem Service) — the Windows process responsible for enforcing security policy and storing cached/hashed credentials for logged-on users. Real-world attackers commonly use tools such as Mimikatz or `procdump` to dump LSASS memory for offline credential extraction.

**Important safety note:** Real LSASS dumping tools (Mimikatz, real `procdump` invocations against LSASS) are detected and quarantined as malware by most antivirus/EDR products, and carry genuine risk even in a home lab. This scenario therefore simulates only the **command-line syntax and reconnaissance pattern** of a credential dumping attempt — no real LSASS memory was accessed or dumped, and no actual dumping tool was executed.

**Simulated attack narrative:**
1. Attacker performs reconnaissance on the `lsass.exe` process using `tasklist` to confirm it is running and identify its presence on the host.
2. Attacker issues a `procdump`-style command targeting `lsass.exe`, simulated via `cmd.exe echo` rather than a real dump, to generate the equivalent command-line evidence safely.
3. (Attempted but not logged as expected) A `findstr`-based search for cached credential files in text/config files — this step did not generate a separate `findstr.exe` process event, as it was simulated via `cmd.exe echo` redirection rather than directly invoking `findstr`.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for command lines containing both `procdump` and `lsass`.
2. Queried Event ID 4688 for `tasklist.exe` invocations filtering on `lsass`.
3. Queried Event ID 4688 for `findstr.exe` invocations referencing `password` — returned 0 events.
4. Combined all LSASS-related and credential-search indicators into a single chronological view.
5. Reviewed why the `findstr` step did not appear as expected, and confirmed it was a simulation artifact rather than a detection gap.

---

## Findings

| Time | Account | Process | Command Line | Significance |
|---|---|---|---|---|
| 2026-06-24 19:21:17.529 | hp | cmd.exe | `cmd.exe /c echo procdump.exe -accepteula -ma lsass.exe C:\Users\hp\AppData\Local\Temp\lsass_dump.dmp` | Simulated LSASS memory dump command (T1003.001) |
| 2026-06-24 19:21:25.356 | hp | tasklist.exe | `tasklist /fi "imagename eq lsass.exe"` | LSASS process reconnaissance, preceding the simulated dump attempt |

**Simulation artifact noted:** The intended `findstr /si password *.txt *.xml *.config` step did not generate a `findstr.exe` process event. This is because the command was wrapped in `cmd.exe /c echo ... > file`, which only logs `cmd.exe` as the executing process rather than directly invoking `findstr.exe`. This is documented as an artifact of how the simulation was constructed — not a logging or detection failure — and is a useful reminder that command wrapping (`echo`, redirection) can obscure the true child process in a real investigation as well, reinforcing the importance of reviewing full command-line context rather than process name alone.

---

## Attack Timeline

```
19:21:17  →  Simulated procdump-style command targeting lsass.exe (T1003.001)
19:21:25  →  tasklist reconnaissance confirming lsass.exe presence
```

*Note: in a real attack, reconnaissance (tasklist) would typically precede the dump attempt. The order observed here reflects the simulation execution sequence, not a literal real-world attack chronology, and is flagged for analytical transparency.*

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |

---

## Verdict & Analysis

This simulation successfully demonstrates the command-line signatures associated with LSASS credential dumping — one of the highest-impact techniques in the MITRE ATT&CK framework, since successful execution can yield credentials for every account that has logged on to the host. Detection relied on Event ID 4688 (Process Creation), filtering on command lines referencing `lsass` in combination with dumping-tool syntax (`procdump`) or reconnaissance utilities (`tasklist`).

Both indicators are high-fidelity: legitimate administrative use of `procdump` against `lsass.exe`, or `tasklist` filtered specifically for `lsass.exe`, is rare outside of dedicated security tooling or forensic investigation. Any occurrence of either pattern from a standard user or unexpected account should be treated as a high-priority alert.

The investigation also reinforced an important analytical lesson: process-name-based detection can be incomplete when commands are wrapped through intermediary shells (`cmd.exe /c echo ...`), since the wrapping process — not the "real" target binary — is what gets logged. Real attackers may exploit this same effect deliberately to evade naive detection logic.

**Verdict:** 🔴 Confirmed simulated credential dumping attempt — LSASS targeting and reconnaissance successfully detected via native Windows process logging.

---

## Response Actions

**Immediate:**
- Investigate the source of the `procdump`-referencing command line and the `tasklist` query targeting `lsass.exe` tied to the `hp` account.
- Verify no actual `.dmp` file was created in `%TEMP%` or elsewhere on the host.
- Review LSASS process access events (Sysmon Event ID 10, if available) for any genuine memory-read attempts in the same timeframe.

**Recommended:**
- Enable Credential Guard and LSA Protection (RunAsPPL) to prevent unauthorized access to LSASS memory, even by processes running with administrative privileges.
- Build a correlation rule alerting on any command line containing both `lsass` and a known dumping-tool reference (`procdump`, `mimikatz`, `comsvcs.dll`, `rundll32 ... MiniDump`).
- Alert on `tasklist` or `Get-Process` queries specifically filtered for `lsass.exe`, since this is uncommon outside of security tooling.
- Deploy Sysmon with Event ID 10 (ProcessAccess) monitoring specifically for handles opened to `lsass.exe` by non-standard processes.

---

## Conclusion

Scenario 09 demonstrates detection of credential dumping reconnaissance and command-line signatures targeting LSASS memory — one of the most critical credential access techniques in real-world attacks — using native Windows Event ID 4688 logging in Splunk. The investigation was conducted safely, without executing any real dumping tool or accessing actual LSASS memory, while still producing realistic, high-fidelity detection evidence. A secondary analytical lesson on command-wrapping and process-name limitations was also captured, reflecting the kind of careful, evidence-based reasoning expected of a SOC L1 analyst.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final

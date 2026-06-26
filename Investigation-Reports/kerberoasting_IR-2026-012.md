# Investigation Report — Scenario 11: Kerberoasting

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-012 |
| **Scenario** | Kerberoasting |
| **Date of Simulation** | 26 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK Technique** | T1558.003 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates **Kerberoasting** — a credential access technique in which an attacker with a foothold in an Active Directory environment requests Kerberos service tickets (TGS) for accounts that have a registered Service Principal Name (SPN), typically service accounts. Because these tickets are encrypted with the service account's password hash, an attacker can take the ticket offline and attempt to crack it to recover the plaintext password — often without triggering an account lockout or real-time alert, since requesting a service ticket is normal Kerberos behavior in any AD environment.

**Lab environment note:** Real Kerberoasting requires an actual Active Directory domain controller, since SPNs and Kerberos ticket-granting only exist in a domain context. This lab environment is a standalone Windows host without AD. Accordingly, this scenario simulates only the **command-line signatures** that real Kerberoasting tools and techniques produce — no real domain, SPN, or Kerberos ticket was involved.

**Simulated attack narrative:**
1. Attacker enumerates Service Principal Names across the domain using `setspn.exe -T DOMAIN -Q */*`, a built-in Windows utility commonly abused for Kerberoasting reconnaissance.
2. Attacker references `Rubeus.exe kerberoast`, the most widely used real-world Kerberoasting tool, to request and export service ticket hashes for offline cracking.
3. Attacker uses a native PowerShell/.NET method (`System.IdentityModel.Tokens.KerberosRequestorSecurityToken`) as a tool-less alternative to Rubeus, requesting a Kerberos ticket directly without dropping an external binary.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for command lines containing `setspn`.
2. Queried Event ID 4688 for command lines containing both `Rubeus` and `kerberoast`.
3. Queried Event ID 4688 for PowerShell invocations referencing `KerberosRequestorSecurityToken`.
4. Combined all three indicators into a single chronological view to reconstruct the full Kerberoasting attempt chain.
5. Noted that all three commands were logged under `cmd.exe` rather than the referenced tool/binary names, consistent with the command-wrapping behavior first observed in Scenario 09.

---

## Findings

| Time | Account | Process | Command Line | Significance |
|---|---|---|---|---|
| 2026-06-26 09:30:22.664 | hp | cmd.exe | `echo setspn.exe -T DOMAIN -Q */*` | SPN enumeration — reconnaissance for Kerberoastable accounts |
| 2026-06-26 09:30:28.924 | hp | cmd.exe | `echo Rubeus.exe kerberoast /outfile:...\Temp\kerberoast_hashes.txt` | Rubeus-style ticket extraction tool reference |
| 2026-06-26 09:30:37.835 | hp | cmd.exe | `echo powershell.exe -c "...KerberosRequestorSecurityToken... 'MSSQLSvc/sql01.domain.local:1433'"` | Native PowerShell Kerberos ticket request (tool-less technique) |

**Command-wrapping observation (recurring pattern):** As previously identified in Scenario 09 (Credential Dumping), all three simulated commands were logged with `cmd.exe` as the executing process, since each was constructed using `echo` rather than directly invoking the referenced binary. This is the second scenario in this campaign to surface this exact analytical point, reinforcing it as a genuine, recurring SOC consideration: detection logic relying on process name alone (`New_Process_Name="*setspn.exe"` or `*Rubeus.exe`) would have missed all three events here, whereas filtering on `Process_Command_Line` content caught them regardless of the wrapping shell.

---

## Attack Timeline

```
09:30:22  →  SPN enumeration via setspn.exe (T1558.003 reconnaissance)
09:30:28  →  Rubeus-style kerberoast ticket extraction referenced
09:30:37  →  Native PowerShell Kerberos ticket request (tool-less alternative)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access |

---

## Verdict & Analysis

This simulation successfully demonstrates the command-line signatures associated with Kerberoasting, one of the most damaging credential access techniques in Active Directory environments, since a single cracked service account password can sometimes grant access well beyond what the service itself requires. Detection relied on Event ID 4688 (Process Creation), filtering on command-line content referencing `setspn`, `Rubeus`/`kerberoast`, or `KerberosRequestorSecurityToken`.

All three patterns are high-fidelity indicators in a real AD environment: legitimate administrative use of `setspn` for querying SPNs broadly (`*/*`) is uncommon outside dedicated AD administration, and any reference to `Rubeus` or direct Kerberos ticket request APIs from a non-security-tooling context should be treated as a high-priority alert.

This investigation also reinforced, for the second time in this campaign, the importance of filtering on full command-line content rather than process name alone — a recurring theme that should inform how detection rules are written across this entire lab, not just in scenarios that explicitly call it out.

**Verdict:** 🔴 Confirmed simulated Kerberoasting attempt — SPN enumeration, tool-based ticket extraction, and tool-less native alternative all successfully detected via native Windows process logging.

---

## Response Actions

**Immediate:**
- Investigate the source of the `setspn`, `Rubeus`, and `KerberosRequestorSecurityToken` references tied to the `hp` account.
- In a real AD environment: review which service accounts have SPNs registered and audit their password strength/rotation policy, since Kerberoastable accounts with weak passwords are the actual point of compromise.
- Check for any `.txt`/hash export files matching the referenced output path.

**Recommended:**
- Enforce strong, regularly rotated passwords (25+ characters or managed service accounts/gMSA) for all SPN-registered service accounts, since this is the only true mitigation — detection alone does not prevent offline cracking once a ticket is exported.
- Build a correlation rule alerting on any `setspn -Q */*` (broad enumeration) or any process referencing `Rubeus`/`kerberoast` in its command line.
- Alert on `KerberosRequestorSecurityToken` usage from non-standard or unexpected processes, since this is rare outside of specific .NET service authentication contexts.
- Enable Windows Event ID 4769 (Kerberos Service Ticket Requested) auditing in a real AD environment, and alert on RC4 encryption type requests specifically, since this is a strong indicator of Kerberoasting (AES tickets are far harder to crack offline).

---

## Conclusion

Scenario 11 demonstrates detection of Kerberoasting — a high-impact Active Directory credential access technique — using command-line signature detection via native Windows Event ID 4688 logging in Splunk, safely simulated without a real domain environment. The investigation reinforced a recurring analytical lesson from this campaign regarding command-wrapping and process-name limitations, and outlined the AD-specific hardening (service account password policy) that would be required to meaningfully mitigate this technique in a production environment, reflecting the broader security context expected of a SOC L1 analyst beyond the immediate lab scope.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final

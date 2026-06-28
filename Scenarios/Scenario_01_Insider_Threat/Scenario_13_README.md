# Scenario 13 — Clipboard & Screen Capture Collection

## 🎯 Objective
Simulate and detect data collection via clipboard monitoring and periodic screen capture — quiet, low-effort techniques that typically precede staging and exfiltration in a real attack chain.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Clipboard Data | T1115 |
| Screen Capture | T1113 |

## 🖥️ Attack Simulation

**1. Clipboard data collection**
```powershell
powershell.exe -Command "Get-Clipboard | Out-File C:\Users\hp\AppData\Local\Temp\clipboard_dump.txt"
```

**2 & 3. Periodic screen capture (two captures, ~9 seconds apart)**
```powershell
powershell.exe -Command "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); $g=[System.Drawing.Graphics]::FromImage($b); $g.CopyFromScreen(0,0,0,0,$b.Size); $b.Save('C:\Users\hp\AppData\Local\Temp\screen_capture.png')"
```

**4. Cleanup**
```cmd
del C:\Users\hp\AppData\Local\Temp\clipboard_dump.txt
del C:\Users\hp\AppData\Local\Temp\screen_capture.png
del C:\Users\hp\AppData\Local\Temp\screen_capture2.png
```

## 🔍 Detection Queries
See [`clipboard_screen_capture_detection.spl`](../../SPL-Queries/clipboard_screen_capture_detection.spl) for the full query set, including the aggregation-based repeated-capture detection query.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 22:38:07 | Clipboard captured to file | T1115 |
| 22:38:20 | First screen capture saved | T1113 |
| 22:38:29 | Second screen capture saved (~9s later) | T1113 — periodic pattern confirmed |

**Real SOC lesson:** a single screenshot event could plausibly be legitimate user activity, but **counting repeated captures per account within a time window** (2+ in this case) is a meaningfully stronger, aggregation-based detection signal than simple keyword matching alone.

## 🟠 Verdict
Confirmed simulated clipboard and screen capture collection — both techniques detected, with the repeated-capture pattern adding additional confidence via aggregation analysis.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/clipboard_screen_capture_IR-2026-014.md`](../../Investigation-Reports/clipboard_screen_capture_IR-2026-014.md)
- Formal incident report: [`Incident-Reports/IR-2026-014_Clipboard_Screen_Capture.docx`](../../Incident-Reports/IR-2026-014_Clipboard_Screen_Capture.docx)
- SPL queries: [`SPL-Queries/clipboard_screen_capture_detection.spl`](../../SPL-Queries/clipboard_screen_capture_detection.spl)

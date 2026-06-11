# test-03-Get-Process

| Field | Details |
| --- | --- |
| **Date** | 2026-06-11 |
| **Test** | #3 - Process Discovery via Get-Process |
| **Tactic** | Discovery |
| **Result** | Detected |

---

## 1. Test Number Overview

This test demonstrates process discovery via PowerShell's `Get-Process` cmdlet. Atomic Red Team executes it by spawning a child PowerShell process from a parent PowerShell session, resulting in a PowerShell-spawns-PowerShell pattern visible in Sysmon logs.

---

## 2. Hypothesis

| Field | Expected |
| --- | --- |
| **Process** | A child PowerShell process will be spawned by the parent PowerShell session |
| **Parent chain** | powershell.exe → powershell.exe |
| **Command line** | Get-Process visible in CommandLine |
| **Event codes** | EventCode=1 (process creation) |

**Expected search:**

```
index=main host="DESKTOP-9KP1CU3"
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*Get-Process*"
```

---

## 3. Execution of Atomic Red Team to start the scenario

| Field | Details |
| --- | --- |
| **Command** | `Invoke-AtomicTest T1057 -TestNumbers 3` |
| **Exit code** | 0 (success) |
| **Issues** | None |

---

## 4. What Splunk Found

| Field | Value |
| --- | --- |
| **Image** | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| **CommandLine** | "powershell.exe" & {Get-Process} |
| **ParentImage** | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| **ParentCommandLine** | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" |
| **User** | DESKTOP-9KP1CU3\SOC101 |
| **Event codes triggered** | EventCode 1 (process create) |

**Detection search:**

```
index=main host="DESKTOP-9KP1CU3"
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="*Get-Process*" 
| where NOT match(Image, "(?i)splunk")
```

**Screenshots:**

Query Result:

![query_result.png](query_result.png)

Log Contents:

![result_examination_1.png](result_examination_1.png)

![result_examination_2.png](result_examination_2.png)

---

## 5. Findings and Expectations

As stated on the hypothesis the use of nested exes happened in one certain log that has event code 1. A child PowerShell process (Image) was spawned by a parent PowerShell process (ParentImage), with `Get-Process` visible in the CommandLine. The `CurrentDirectory` being `C:\Users\SOC101\AppData\Local\Temp\` was an unexpected finding — worth flagging as a behavioral indicator in production.

---

## 6. Detection Rule

**Trigger logic:**

| Field | Value |
| --- | --- |
| **Image** | `*powershell.exe*` |
| **ParentImage** | `*powershell.exe*` |
| **CommandLine** | `*Get-Process*` |

**Detection search:**

```
index=main host="DESKTOP-9KP1CU3"
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*Get-Process*" ParentImage="*powershell.exe*" Image="*powershell.exe*"
```

**False positive risk:**
Medium: `Get-Process` is a common cmdlet. In production, this alert would be low-confidence without additional context. 

**Alert configuration:**

| Setting | Value |
| --- | --- |
| **Name** | alert_get-process_attempt |
| **Schedule** | Every 5 mins or `*/5 * * * *` |
| **Lookback** | Last 15 minutes |
| **Trigger** | Number of results > 0, per result |
| **Severity** | Medium |
| **Mode** | Per Result |

**Screenshots:**

Alert:

![image.png](image.png)

Alert Triggered:

![alert_triggered.png](alert_triggered.png)

---

## 7. Cleanup + Next Steps

**Cleanup:**

```powershell
Invoke-AtomicTest T1057 -TestNumbers 3 -Cleanup
```

---

## 8. Takeaways
In normal environments, a process spawning another instance of itself is uncommon and worth investigating. Seeing powershell.exe as both the Image and ParentImage is a behavioral anomaly, legitimate admin scripts typically run Get-Process inline within the same session, not by launching a child PowerShell process.

The CurrentDirectory being AppData\Local\Temp is also a red flag. Legitimate PowerShell scripts are usually executed from structured directories like `C:\Scripts` or `C:\Windows\System32`, not a temp folder.

Additionally, `Get-Process` alone is a weak detection signal in production since it's too common. The real detection value here comes from the combination: same binary spawning itself, running from a temp directory, at High integrity level. No single indicator is enough; context is everything.

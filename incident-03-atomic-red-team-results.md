# Incident Report 03: Atomic Red Team Tests and a Scheduled Task Detection Gap

- **Environment:** Home lab, simulated activity
- **Host:** SOC-WIN11-LAB (Windows 11 with Sysmon)
- **Detection source:** Wazuh 4.14.8, Sysmon and Windows Security event logs
- **Date:** 2026-10-25
- **Analyst:** Nithiya Nandhini Dass
- **Highest alert level:** 12

## 1. Summary

I ran a small set of Atomic Red Team tests on the lab VM to see what Wazuh detects. The tests covered account creation, account discovery, a Run key, scheduled tasks and encoded PowerShell. Most of them were detected. Scheduled task creation was not: it only produced low level alerts with the wrong technique tag. I wrote two rules for it (100102 and 100103). My first version of 100103 also matched the command that deletes a task, and I fixed that.

## 2. How I ran the tests

I excluded `C:\AtomicRedTeam` from Defender, installed Invoke-AtomicRedTeam on the VM and listed the tests with `-ShowDetailsBrief`. I picked tests that only create test accounts, list accounts, add a Run key or a scheduled task, or print text, and I ran the cleanup commands for them afterwards.

I skipped tests that download tools or exploit scripts, such as the Mimikatz, BloodHound and SOAPHound tests under T1059.001. Test T1059.001-15 did not run because it needs a helper module that was not installed (`Out-ATHPowerShellCommandLineParameter` was not recognized).

Times below are Eastern (EDT), as shown by the manager. The VM clock was about 10 minutes behind the manager until I fixed it with `w32tm /resync`.

## 3. Results

| Technique | Test | What Wazuh raised | Level |
|---|---|---|---|
| T1136.001 Create account | -4 (cmd, `net user /add`) | 92040 "net1.exe executed a user creation command", tagged T1136.001 | 12 |
| | | 60109 "User account enabled or created" and 60110 "User account changed" (event log) | 8 |
| | | 92036, 92052 (net.exe started by cmd) | 3 and 4 |
| T1136.001 Create account | -5 (PowerShell, `New-LocalUser`) | 60109 and 60110 (event log) | 8 |
| | | 92027 "Powershell process spawned powershell instance" | 4 |
| T1087.001 Account discovery | -8 and -9 | 92031, 92033 "Discovery activity executed" (T1087), 92032, 92036 | 3 |
| | | 92027, 92052 | 4 |
| T1547.001 Run key | -1 | 92302 "Registry entry to be executed on next logon was modified using reg.exe", tagged T1547.001 | 6 |
| T1053.005 Scheduled task | -2 and -4 | Before my rules: 92032 (tagged T1087 and T1059.003) and 92027 (tagged T1059.001) | 3 and 4 |
| T1059.001 PowerShell | -17 | 92057 "Powershell.exe spawned a powershell process which executed a base64 encoded command", tagged T1059.001 | 12 |

Notes on the account creation test:

- Both methods raised the event log alerts (60109, 60110), so an account created with PowerShell is still caught even though the command line rule only rates it level 4.
- I ran the creation tests twice (about 19:22 and 19:25) without cleaning up in between. The event log alerts 60109 and 60110 appear only for the first run. I think the second creation failed because the accounts already existed, but I did not check that. The command line alerts appear both times.

## 4. Encoded PowerShell: four forms of the switch

I ran the same harmless encoded command in four forms from a PowerShell prompt:

```powershell
$b = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host lab-test'))
powershell -EncodedCommand $b
powershell -enc $b
powershell -e $b
powershell -ec $b
```

I ran the set twice and got the same result both times.

| Form | Rule that fired | Level |
|---|---|---|
| `-EncodedCommand` | 92057 (built-in) | 12 |
| `-enc` | 100100 (my rule from Incident 02) | 10 |
| `-e` | 92057 (built-in) | 12 |
| `-ec` | 92057 (built-in) | 12 |

Each form produced one alert. The built-in rule 92057 caught three of the four forms, and my rule 100100 caught `-enc`, which 92057 did not alert on. I have not read the source of rule 92057, so this describes what I saw, not how the rule is written.

This changes what I wrote in Incident 02. I said that 100100 misses `-e` and `-ec`. That is true for my rule, but those forms are covered by the built-in rule, so there was no gap in practice.

## 5. Detection gap: scheduled tasks (T1053.005)

I created tasks in two ways:

```
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
New-ScheduledTaskAction ... Register-ScheduledTask AtomicTask ...
```

Wazuh did raise alerts (19:34:49 and 19:34:50), but only rule 92032 at level 3 and rule 92027 at level 4. Neither was tagged T1053.005, and 92032 was tagged T1087 (account discovery), which is the wrong technique. A search for alerts tagged T1053.005 or T1547.001 in that time window returned only the Run key alert. Scheduled tasks are a common persistence method, so I wrote two rules in `rules/100102_scheduled_task_persistence.xml`:

- **100102** is a child of 92032 and matches `schtasks ... /create` in the command line.
- **100103** is a child of 92027 and matches `Register-ScheduledTask` in the command line.

Both are level 8 with MITRE T1053.005. I chose level 8 and not higher because administrators also create scheduled tasks.

### A bug in my first version

My first version of 100103 matched `(Register-ScheduledTask|New-ScheduledTask)`. When the test cleanup ran `Unregister-ScheduledTask`, rule 100103 fired at 19:47:52, because "Unregister-ScheduledTask" contains "Register-ScheduledTask". A rule that alerts when a task is removed is a false positive. I changed the pattern to `\bRegister-ScheduledTask\b`, which needs a word boundary before the name, and dropped `New-ScheduledTask`, since `Register-ScheduledTask` is the cmdlet that actually creates the task.

### Result after the fix

I ran the creation test and the cleanup once more and checked the alerts:

| Time (EDT) | Rule | Level | Command |
|---|---|---|---|
| 20:00:52 | 100102 | 8 | `SCHTASKS /Create /SC ONCE /TN spawn ...` |
| 20:00:54 | 100103 | 8 | `New-ScheduledTaskAction ... Register-ScheduledTask AtomicTask` |
| 20:01:01 | 92032 | 3 | `SCHTASKS /Delete /TN spawn /F` (cleanup) |
| 20:01:01 | 92027 | 4 | `Unregister-ScheduledTask -TaskName "AtomicTask"` (cleanup) |

The creation commands now raise level 8 alerts tagged T1053.005. The cleanup commands fall back to the normal low level alerts. Before testing I ran `wazuh-analysisd -t` and restarted the manager.

## 6. Other alerts in the same period

Right after the agent reconnected (about 19:22) Wazuh raised several alerts that were not part of my tests:

- Rule 92219 "Possible DLL search order hijack" (level 6) and rule 92217 "Executable dropped in Windows root folder" (level 6). The files were under `C:\Windows\SoftwareDistribution\Download\...` and `C:\Windows\SystemTemp\{GUID}\ssshim.dll`.
- Rule 61634 "Sysmon - Suspicious Process - taskhost.exe" (level 12) for `backgroundTaskHost.exe -ServerName:App.AppX...`.
- Rule 19005, a Security Configuration Assessment summary (score below 30%) for the CIS Windows 11 benchmark.

I think the first three are normal Windows Update and Store app activity, because of the paths and the process name. I did not investigate them further, so I have not tuned them. The CIS score only says the default VM is not hardened to that benchmark.

## 7. MITRE ATT&CK mapping

| Behavior | Technique |
|---|---|
| Local account created | T1136.001, Create Account: Local Account |
| Local account discovery | T1087.001, Account Discovery: Local Account |
| Run key persistence | T1547.001, Registry Run Keys / Startup Folder |
| Scheduled task persistence | T1053.005, Scheduled Task/Job: Scheduled Task |
| PowerShell command execution | T1059.001, Command and Scripting Interpreter: PowerShell |
| Base64 encoded command | T1027, Obfuscated Files or Information |

## 8. What I learned

- Two detection layers can catch the same action in different ways. Account creation was caught by the command line rules and by the event log rules, and each rated it differently.
- Testing a rule has to include the cleanup commands. My rule matched the command that removes a task until I tested that.
- A word like "Register" can appear inside another word, so patterns need word boundaries.
- Checking a gap before writing a rule saved me from a wrong conclusion. I first thought `New-LocalUser` was undetected, but the event log rule caught it.
- Keep the VM clock in sync with the manager. A 10 minute difference made my own timeline hard to follow.

## 9. Limits and open items

- Rule 100103 is a child of 92027, so it only fires when PowerShell is started by PowerShell, like rule 100100. A task created through another route, such as the Task Scheduler interface or another program, may not match.
- Rule 100102 depends on 92032 firing for `schtasks.exe`. I only tested it from cmd.exe.
- I ran only a few tests per technique. A different test of the same technique may behave differently.
- I did not tune the alerts listed in section 6.

# Incident Report 02: Encoded PowerShell and a Noisy Level 15 Rule

- **Environment:** Home lab, simulated activity
- **Host:** SOC-WIN11-LAB (Windows 11 with Sysmon)
- **Detection source:** Wazuh 4.14.8, Sysmon process creation events
- **Date:** 2026-10-10
- **Analyst:** Nithiya Nandhini Dass
- **Severity:** Informational. The command only prints text. The point of this report is how Wazuh handled it.

## 1. Summary

I ran a harmless PowerShell command with the `-enc` switch, which takes a Base64 encoded command. Attackers use it to hide what a command does. Wazuh recorded the full command line, but only as a level 4 alert with a generic description. I wrote a custom rule that raises it to level 10 and adds MITRE tags. I also found that a built-in level 15 rule fires every time PowerShell starts, and I wrote a tuning rule for it.

## 2. The test

```powershell
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==
```

The string decodes to `Write-Host "test"`.

## 3. Default detection

| Time (EDT) | Rule | Level | Description |
|---|---|---|---|
| 14:04:56 | 92027 | 4 | Powershell process spawned powershell instance |
| 14:39:01 | 92027 | 4 | Powershell process spawned powershell instance |
| 14:46:49 | 92027 | 4 | Powershell process spawned powershell instance |

The alert contains the whole command line, including the encoded string. Nothing in the description mentions encoding, and at level 4 it would not show up if an analyst only looked at level 7 and above.

## 4. Custom rule 100100

The rule is saved in its own file, `/var/ossec/etc/rules/100100_encoded_powershell.xml`:

```xml
<group name="sysmon,powershell,">
  <rule id="100100" level="10">
    <if_sid>92027</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-(enc|encodedcommand)\s</field>
    <description>Encoded PowerShell command executed</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
  </rule>
</group>
```

At 14:49:33 the rule fired at level 10 with MITRE T1059.001 and T1027, and the alert showed the full command line.

My first version used `<if_group>sysmon_event1</if_group>` and never fired. Making the rule a child of 92027 with `<if_sid>` fixed it. I think rule 92027 was matching the event first, but I also changed the regular expression between the two versions, so I cannot say for sure which change fixed it.

## 5. False positive: rule 92213 at level 15

| Time (EDT) | Rule | Level | Description |
|---|---|---|---|
| 14:46:49 | 92213 | 15 | Executable file dropped in folder commonly used by malware |
| 14:49:33 | 92213 | 15 | Executable file dropped in folder commonly used by malware |

I looked at the alert fields:

- File: `C:\Users\socanalyst\AppData\Local\Temp\__PSScriptPolicyTest_<random>.ps1`
- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `SOC-WIN11-LAB\socanalyst`

I judged this a false positive. PowerShell creates a `__PSScriptPolicyTest_*.ps1` file in the Temp folder when it starts, as a check of the execution policy. The process is the normal PowerShell program, run by the logged-in user, and the file name follows PowerShell's own pattern. The alert appeared each time I started PowerShell, so at level 15 it would flood an analyst's queue.

### Tuning rule 100101

I added a child rule of 92213 in `/var/ossec/etc/rules/100101_psscriptpolicytest_tuning.xml`. It matches `__PSScriptPolicyTest_` in the file name and lowers the level to 3. I kept the level at 3 instead of 0 so the event is still logged and searchable.

```xml
<group name="sysmon,tuning,">
  <rule id="100101" level="3">
    <if_sid>92213</if_sid>
    <field name="win.eventdata.targetFilename" type="pcre2">__PSScriptPolicyTest_</field>
    <description>Tuned: PowerShell execution policy test file (benign, was rule 92213)</description>
  </rule>
</group>
```

I checked the field name `targetFilename` in the JSON of an existing 92213 alert before writing the rule. I ran `wazuh-analysisd -t` (exit code 0) and then restarted the manager.

| Time (EDT) | Rule | Level | Result |
|---|---|---|---|
| 14:49:33 | 92213 | 15 | Before tuning: `__PSScriptPolicyTest_2dsbmdiv.2br.ps1` flagged as malware-like |
| 15:03:55 | 100100 | 10 | After tuning: the encoded command is still detected |
| 15:03:55 | 100101 | 3 | After tuning: `__PSScriptPolicyTest_dporsdnp.0sl.ps1` is logged as benign |

After the tuning rule was in place, no new level 15 alert appeared for this file.

## 6. MITRE ATT&CK mapping

| Behavior | Technique |
|---|---|
| PowerShell command execution | T1059.001, Command and Scripting Interpreter: PowerShell |
| Base64 encoded command | T1027, Obfuscated Files or Information |

## 7. What I learned

- Wazuh can record an event and still rate it too low, so alert levels need checking against the behavior.
- A rule that overlaps with a built-in rule may need to be built as a child of it.
- A mistake in `local_rules.xml` stopped the whole manager, so I now run `wazuh-analysisd -t` before every restart.
- A level 15 alert is not always malicious. The file, process and user showed this one was normal.

## 8. Limits and open items

- Rule 100100 is a child of 92027, so it only fires when PowerShell is started by PowerShell. An encoded command started from `cmd.exe` or another program would probably not match. The regular expression also misses the short forms of the switch, such as `-e` and `-ec`. A better version would be built on the general Sysmon process creation rule.
- Other alerts appeared on the same VM around 14:05 (a level 9 PowerShell alert and `net user` commands) and at 14:57 (rule 92058, level 12, "Application Compatibility Database launched"). I did not record what caused them, so I left them out of this report.

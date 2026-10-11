# Incident Report 01: Local Admin Account Created and Deleted

- **Environment:** Home lab, simulated activity
- **Host:** SOC-WIN11-LAB (Windows 11)
- **Detection source:** Wazuh 4.14.8, Windows Security event log
- **Date:** 2026-10-10
- **Analyst:** Nithiya Nandhini Dass
- **Highest alert level:** 12

## 1. Summary

I created a local user account named `labtest`, added it to the local Administrators group, and deleted it a short time later. This copies a common persistence technique, where an attacker creates a hidden admin account. Wazuh raised an alert for each step. The Administrators group change was the highest, at level 12.

## 2. Timeline

Times are Eastern (EDT). Wazuh's raw logs use UTC, which is four hours ahead.

| Time (EDT) | Wazuh rule | Level | Description |
|---|---|---|---|
| 13:42:05 | 60122 | 5 | Logon failure, unknown user or bad password |
| 13:42:45 | 60109 | 8 | User account enabled or created |
| 13:42:45 | 60110 | 8 | User account changed |
| 13:42:45 | 60154 | 12 | Administrators group changed |
| 13:42:45 | 60111 | 8 | User account disabled or deleted |

Rules 60160 and 60170 (group changes, level 5) also fired at 13:42:45. Some alerts appear twice because one command can write several Windows events.

I ran the failed logon several times. Counting Event ID 4625 in `alerts.log` returned 4, and the table shows one of them.

## 3. Evidence

The deletion matches Windows Event ID 4726 at 17:42:44 UTC:

- Account that performed the action: `socanalyst`
- Account that was deleted: `labtest`
- Host: `SOC-WIN11-LAB`

I listed the alerts with this command on the manager:

```bash
sudo grep "SOC-WIN11-LAB" /var/ossec/logs/alerts/alerts.json \
  | jq -c '{time: .timestamp, rule: .rule.id, level: .rule.level, desc: .rule.description, mitre: .rule.mitre.id}'
```

## 4. MITRE ATT&CK mapping

| What happened | Technique | Note |
|---|---|---|
| Local account created | T1136.001, Create Account: Local Account | Wazuh tagged this as T1098. T1136.001 fits account creation better. |
| Account added to Administrators | T1098, Account Manipulation | Matches the Wazuh tag. |
| Group membership changed | T1484 (Wazuh tag) | T1484 is mainly about domain policy changes. For a local group, T1098 looks like the better fit. |
| Account deleted | T1531, Account Access Removal (Wazuh tag) | In this test the deletion was cleanup of my own test account. |

## 5. Analysis

- Create, elevate and delete within about a minute is a typical persistence and cleanup pattern.
- The level 12 alert on the Administrators group is the one to look at first, because it is the privilege change.
- The account that made the change was an existing local account, `socanalyst`. In a real case the next question would be whether that account should be making admin changes.
- A failed logon 40 seconds earlier would be worth checking in a real case. It could mean someone was guessing passwords before getting in.

## 6. What I would do in a real incident

1. Check whether the account creation was approved.
2. If not, disable the account that made the change, reset its password, and isolate the host.
3. Look at other logons by that account around the same time.
4. Check for other persistence, such as services, scheduled tasks and run keys.
5. Add an alert for admin group changes outside working hours.

## 7. Open items

- Alerts 60154, 60160 and 60111 also appear at 13:40:50, before the test above. I did not record what caused them, so I left them out of the timeline.
- This report has no process information, so I cannot see which process ran the account commands. Sysmon was added afterwards (see Incident 02).

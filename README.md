# Wazuh SIEM Home Lab

A small SOC lab I built at home. A Windows 11 virtual machine sends its logs to a Wazuh manager. I ran some test activity on the VM, investigated the alerts, mapped them to MITRE ATT&CK, and wrote custom detection rules. All activity is simulated in my own lab.

## Lab setup

| Part | Details |
|---|---|
| Wazuh manager | Ubuntu 24.04 on WSL2, Wazuh 4.14.8 |
| Endpoint | Windows 11 VM named `SOC-WIN11-LAB` in VMware Workstation |
| Agent | Wazuh Windows agent 4.14.8 |
| Extra logging | Sysmon on the endpoint |
| Network path | VM, then the Windows host, then WSL, to the manager on ports 1514 and 1515 |

```
[Windows 11 VM]  --1514/tcp-->  [Windows host (NAT)]  -->  [Wazuh manager in WSL]
 SOC-WIN11-LAB                     172.27.96.1                 172.27.96.226
```

The WSL address changes after a restart. Check it with `hostname -I` and update the manager address in the agent's `ossec.conf` if it changes.

## What I did

1. Installed the Wazuh manager in WSL and the Wazuh agent on the VM.
2. Fixed the problems that stopped the agent from connecting (see below).
3. Created test events on the VM: failed logons, a new local admin account, an account deletion, and an encoded PowerShell command.
4. Read the alerts in `alerts.json` with `jq` and wrote an incident report for each case.
5. Wrote a custom rule for encoded PowerShell and a tuning rule for a false positive.
6. Ran a small set of Atomic Red Team tests, found a gap in scheduled task detection and wrote two rules for it.

## Incident reports

| # | Report | MITRE ATT&CK |
|---|---|---|
| 1 | [Local admin account created and deleted](incident-01-backdoor-admin-account.md) | T1136.001, T1098 |
| 2 | [Encoded PowerShell and a noisy level 15 rule](incident-02-encoded-powershell-detection.md) | T1059.001, T1027 |
| 3 | [Atomic Red Team tests and a scheduled task detection gap](incident-03-atomic-red-team-results.md) | T1136.001, T1087.001, T1547.001, T1053.005, T1059.001 |

## Custom rules

The rules are in the [rules](rules) folder.

| Rule | Level | Purpose |
|---|---|---|
| 100100 | 10 | Raises encoded PowerShell commands from level 4 to level 10 |
| 100101 | 3 | Lowers a false positive from rule 92213 (level 15) |
| 100102 | 8 | Scheduled task created with `schtasks /create` (T1053.005) |
| 100103 | 8 | Scheduled task created with `Register-ScheduledTask` (T1053.005) |

## Problems I ran into

**1. Copy and paste did not work between my PC and the VM.**
I could not paste the agent key into the VM. I served the key file from the manager with a temporary `python3 -m http.server`, downloaded it in the VM with PowerShell, and deleted the file afterwards.

**2. The agent stayed on "Never connected" even with the right key.**
The manager log said `Message from '172.27.96.1' not allowed. Cannot find the ID of the agent.` The agent was registered with its own IP (`192.168.154.129`), but WSL's NAT made the traffic arrive from the Windows host (`172.27.96.1`), so the manager rejected it. I removed agent 001 and registered the agent again with the IP set to `any`. It became agent 002, I made sure the key on the VM matched, and the agent turned Active.

**3. The agent window said "Admin access required".**
I worked from an elevated PowerShell instead of the window.

**4. No Sysmon events reached Wazuh.**
Sysmon was logging on the VM, but the agent's `ossec.conf` had no `localfile` entry for the Sysmon event channel. After I added it and restarted the agent, Sysmon alerts appeared.

**5. A mistake in my rules file stopped the whole manager.**
I edited `local_rules.xml` in nano and broke it. `wazuh-analysisd` could not load the rules, the other daemons stopped, and `agent_control` could no longer reach `wazuh-db`. The log said `Invalid root element "if_sid"`. I replaced the file with the default one, moved my rules into separate files, and now run `wazuh-analysisd -t` before every restart.

**6. My first version of rule 100100 never fired.**
It was attached to the Sysmon process group. Making it a child of the built-in rule 92027 fixed it. See Incident 02 for details.

**7. Atomic Red Team would not install.**
PowerShell blocked the module's scripts because the execution policy was Restricted. I changed the policy for that one PowerShell window only with `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, and the install worked.

**8. My commands found nothing because I was in the wrong Ubuntu.**
I had two Ubuntu distributions in WSL, and the plain `Ubuntu` one had no Wazuh. The lab is in `Ubuntu-24.04`, which I now open with `wsl -d Ubuntu-24.04`.

**9. The VM clock was about 10 minutes behind the manager.**
Times in my own notes did not match the alerts. I fixed it with `w32tm /resync`.

## What I learned

- Wazuh checks the source IP of each agent, so NAT between the agent and the manager can break an agent that was registered with a fixed IP.
- The manager log often explains a connection problem better than the agent log.
- Wazuh stores times in UTC. Ontario time (EDT) is four hours behind.
- The MITRE tags that Wazuh adds are a starting point and need checking.
- A high alert level does not always mean something malicious. I checked the file, process and user before judging rule 92213.
- Test the rules with `wazuh-analysisd -t` before restarting the manager.
- Test a rule against the cleanup commands too. My first scheduled task rule also matched the command that deletes a task.
- Two detection layers can catch the same action. Account creation was caught by command line rules and by event log rules.

## Not done yet

- I ran only a few Atomic Red Team tests (account creation, account discovery, a Run key, scheduled tasks and encoded PowerShell). I skipped the tests that download tools such as Mimikatz and BloodHound.
- I did not install the Wazuh dashboard. I read alerts from the log files.

## Evidence

Screenshots from the lab are in [wazuh-SOC-lab-evidence.pdf](wazuh-SOC-lab-evidence.pdf). They show the connected agent, the Incident 01 alerts, Sysmon running, the default alert for the encoded command, rule 100100 firing, the false positive, the before and after result of the tuning rule, and the Incident 03 alerts (account creation, the four forms of encoded PowerShell, the scheduled task before and after rules 100102 and 100103, the Run key, and other alerts from the VM).

Author: Nithiya Nandhini Dass

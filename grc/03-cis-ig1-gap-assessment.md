# CIS Controls v8 (IG1) Gap Assessment – Wazuh SOC Lab

Scope: Assets A-01, A-02, A-03, C-01 (see 01-asset-inventory.md)
Assessment date: Nov 2026 | Assessor: Nithiya Nandhini Dass
Status key: Implemented | Partial | Not Implemented | To confirm

## Gap Table
| CIS | Safeguard | NIST CSF 2.0 | Status | Evidence | Gap | Planned Fix |
|-----|-----------|--------------|--------|----------|-----|-------------|
| 1.1 | Detailed enterprise asset inventory | ID.AM-01 | Implemented | 01-asset-inventory.md | None | Review quarterly |
| 2.1 | Software inventory | ID.AM-02 | Implemented | 01-asset-inventory.md | None | Review quarterly |
| 2.2 | Authorized software is currently supported | PR.PS-02 | Partial | Wazuh manager 4.14.8 rc2 | Release candidate build in use, not a stable release | Upgrade to the stable release |
| 4.1 | Secure configuration process | PR.PS-01 | Not Implemented | 02-sca-baseline.md (Windows 26%, Ubuntu 50%) | No documented hardening baseline; most CIS checks fail | Apply priority CIS Benchmark fixes; re-scan |
| 5.2 | Use unique passwords | PR.AA-01 | Not Implemented | User confirmed some passwords are reused across accounts | Password reuse means one leaked password can unlock several accounts | Use a password manager (e.g. Bitwarden) and set unique passwords, starting with GitHub, email and the lab accounts |
| 5.4 | Admin privileges restricted to dedicated admin accounts | PR.AA-05 | Not Implemented | net localgroup administrators: Administrator, socanalyst; built-in Administrator account disabled (good) | Daily-use account (socanalyst) has full admin rights | Create a separate admin account; make socanalyst a standard user |
| 6.3 | MFA for externally exposed applications (GitHub) | PR.AA-03 | Implemented | GitHub two-factor authentication enabled; Git access uses a fine-grained token (one repo, 90-day expiry) | None | Maintain; rotate token before expiry |
| 7.1 | Vulnerability management process | ID.RA-01 | Partial | Wazuh vulnerability detection enabled in ossec.conf (feed updates every 60 min) | Tool enabled, but no written process for reviewing and fixing findings | Write a short vulnerability management process; review findings regularly |
| 7.3 | Automated OS patch management | PR.PS-02 | Partial | Windows: automatic updates working (KB5127648 security update installed by SYSTEM, Nov 2026); Ubuntu: 6 packages with pending updates | Ubuntu updates not applied automatically | Apply Ubuntu updates; enable unattended-upgrades |
| 8.1 | Audit log management process | PR.PS-04 | Partial | Logs collected by Wazuh agent and Sysmon | No written logging policy or retention period | Write Logging and Monitoring Policy (05) |
| 8.2 | Collect audit logs | PR.PS-04, DE.CM-09 | Implemented | Wazuh agent 002 Active; Sysmon 15.22; custom rules 100100–100103 | None | Maintain |
| 8.3 | Adequate audit log storage | PR.PS-04 | Partial | 935 GB free (3% used) on manager disk | Capacity adequate, but no log retention period defined | Define retention in Logging and Monitoring Policy (05) |
| 10.1 | Anti-malware software deployed | DE.CM-09 | Implemented | Microsoft Defender: service enabled, real-time protection on, signatures updated 11 Nov 2026 | None | Maintain; keep signatures current |
| 11.2 | Automated backups | PR.DS-11 | Partial | Custom rules stored in GitHub repo (rules/ folder); diff check confirmed repo copies match live rules (formatting-only differences) | Backups are manual; Wazuh manager configuration (ossec.conf) not backed up | Back up ossec.conf (excluding agent keys); schedule an automated backup with a diff check |
| 17.3 | Process for reporting incidents | RS.CO-02 | Partial | Three incident reports on GitHub | Reports exist, but no written incident reporting process | Write a one-page incident reporting procedure |

## Summary
| Status | Count | Safeguards |
|--------|-------|------------|
| Implemented | 5 of 15 (33%) | 1.1, 2.1, 6.3, 8.2, 10.1 |
| Partial | 7 of 15 (47%) | 2.2, 7.1, 7.3, 8.1, 8.3, 11.2, 17.3 |
| Not Implemented | 3 of 15 (20%) | 4.1, 5.2, 5.4 |

### By NIST CSF 2.0 Function
| Function | Result | Notes |
|----------|--------|-------|
| Govern | Not assessed | No written policies yet; Logging and Monitoring Policy (05) will start this |
| Identify | Strong | Asset and software inventories in place; vulnerability process missing |
| Protect | Weak | Admin rights, password reuse and CIS hardening are the main gaps |
| Detect | Strong | Wazuh, Sysmon, custom rules and Defender all working |
| Respond | Partial | Incident reports exist; no written reporting process |
| Recover | Partial | Manual rule backups only |

### Key Strengths
- Strong detection: centralized logging with Wazuh and Sysmon, custom detection rules, Defender active.
- Built-in Administrator account disabled; Windows patching automatic; GitHub protected with 2FA and a scoped token.
- Rule backups verified against the live system with a diff check.

### Top 3 Priorities
1. **5.4** – Make socanalyst a standard user and use a separate admin account (quick win, high impact).
2. **5.2** – Adopt a password manager and remove password reuse.
3. **4.1** – Apply priority CIS Benchmark fixes on the Windows VM (baseline 26%) and re-scan.

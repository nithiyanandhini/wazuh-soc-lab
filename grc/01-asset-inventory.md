# Asset Inventory – Wazuh SOC Lab

Maps to: CIS Controls v8 – 1.1 (Enterprise Asset Inventory), 2.1 (Software Inventory)
Last reviewed: Nov 2026 | Owner: Nithiya Nandhini Dass

## Hardware / Hosts
| ID | Asset | Type | OS / Version | Purpose | Data Held | Criticality |
|----|-------|------|--------------|---------|-----------|-------------|
| A-01 | Host laptop | Physical | Windows 11 Home 64-bit (Build 26300.9818), 16 GB RAM | Runs WSL and VMware | Personal files, lab files | High |
| A-02 | Wazuh manager | WSL distro | Ubuntu 24.04.5 LTS | SIEM – collects and analyzes logs | Security logs, custom rules | High |
| A-03 | Windows 11 endpoint | VMware VM | Windows 11 Pro 25H2 (Build 26200.9711) | Monitored endpoint, attack testing | Test data only | Medium |

## Software
| ID | Software | Version | Installed On | Purpose |
|----|----------|---------|--------------|---------|
| S-01 | Wazuh manager | 4.14.8 (rc2) | A-02 | SIEM |
| S-02 | Wazuh agent | ____ | A-03 | Log forwarding |
| S-03 | Sysmon | 15.22 | A-03 | Detailed endpoint logging |
| S-04 | Atomic Red Team | Installed via Invoke-AtomicRedTeam | A-03 | Attack simulation |
| S-05 | VMware Workstation Pro | 25H2 (25.0.0.24995812) | A-01 | Virtualization |

## Cloud / External
| ID | Asset | Purpose | Data Held | Criticality |
|----|-------|---------|-----------|-------------|
| C-01 | GitHub repo (wazuh-soc-lab) | Stores rules, reports, docs | Public lab documentation | Medium |

## Notes
- Wazuh manager is a release candidate build (rc2), not a final stable release.
- Host laptop runs Windows 11 Home, which has no Group Policy Editor; some CIS Benchmark settings cannot be enforced the standard way.

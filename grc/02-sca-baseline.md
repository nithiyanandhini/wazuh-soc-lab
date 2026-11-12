# SCA Baseline – CIS Benchmark Results

Tool: Wazuh Security Configuration Assessment (SCA), Wazuh 4.14.8
Scan date: 11 Nov 2026 | Raw evidence: sca-baseline-raw.json
Framework mapping (from Wazuh): SOC 2 TSC CC7.1, CC7.2 | NIST 800-53 CM-1 | PCI DSS 2.2

## Baseline Results
| Asset | Benchmark | Passed | Failed | Invalid | Total | Score |
|-------|-----------|--------|--------|---------|-------|-------|
| A-02 Wazuh manager (Ubuntu 24.04.5) | CIS Ubuntu Linux 24.04 LTS v1.0.0 | 104 | 101 | 74 | 279 | 50% |
| A-03 Windows 11 Pro VM | CIS Microsoft Windows 11 Enterprise v3.0.0 | 123 | 345 | 14 | 482 | 26% |

## Initial Observations
- The Windows 11 endpoint is well below a secure configuration baseline (26%).
- The Wazuh manager passes about half of the CIS checks (50%).
- 74 Ubuntu checks returned "invalid", likely because WSL does not support some system-level settings. This limits assessment coverage.
- The Windows VM runs Windows 11 Pro, but the benchmark used is the Enterprise version, so some checks may not fully apply.

## After Remediation
(To be completed after fixes.)

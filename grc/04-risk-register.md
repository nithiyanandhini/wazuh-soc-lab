# Risk Register – Wazuh SOC Lab

Owner: Nithiya Nandhini Dass | Created: Nov 2026 | Review: monthly
Sources: 03-cis-ig1-gap-assessment.md, 02-sca-baseline.md, assessment observations

## Scoring Method
- Likelihood (L): 1 Rare, 2 Unlikely, 3 Possible, 4 Likely, 5 Almost certain
- Impact (I): 1 Minimal, 2 Minor, 3 Moderate, 4 Major, 5 Severe
- Score = L x I | Rating: 1–6 Low, 8–12 Medium, 15–25 High
- Risk appetite: High risks treated within 30 days; Medium within 90 days; Low may be accepted with justification.

## Register
| ID | Risk | Asset | CIS | L | I | Score | Rating | Treatment | Planned Action | Due | Status |
|----|------|-------|-----|---|---|-------|--------|-----------|----------------|-----|--------|
| R-01 | Daily-use account has admin rights, so malware or a mistake runs with full privileges | A-03 | 5.4 | 4 | 4 | 16 | High | Mitigate | Create separate admin account; make socanalyst a standard user | Nov 2026 | Open |
| R-02 | Password reuse means one leaked password could unlock several accounts | All | 5.2 | 4 | 4 | 16 | High | Mitigate | Adopt a password manager; set unique passwords, starting with GitHub and email | Nov 2026 | Open |
| R-03 | Windows VM fails most CIS Benchmark checks (26%), leaving weak security settings | A-03 | 4.1 | 3 | 4 | 12 | Medium | Mitigate | Apply priority CIS fixes; re-scan with Wazuh SCA | Dec 2026 | Open |
| R-04 | Ubuntu manager has pending updates and no automatic patching | A-02 | 7.3 | 3 | 3 | 9 | Medium | Mitigate | Apply updates; enable unattended-upgrades | Nov 2026 | Open |
| R-05 | Wazuh manager configuration is not backed up; a WSL failure could lose settings | A-02 | 11.2 | 3 | 3 | 9 | Medium | Mitigate | Back up ossec.conf (excluding agent keys) to the repo; schedule automated backup | Dec 2026 | Open |
| R-06 | No written vulnerability management process, so findings may not be reviewed or fixed | A-02, A-03 | 7.1 | 3 | 3 | 9 | Medium | Mitigate | Write a short vulnerability management process | Dec 2026 | Open |
| R-07 | Wazuh manager runs a release candidate (rc2) build that may contain unfixed bugs | A-02 | 2.2 | 2 | 3 | 6 | Low | Mitigate | Upgrade to the stable release | Dec 2026 | Open |
| R-08 | No logging policy or retention period, so log handling is inconsistent | A-02 | 8.1, 8.3 | 2 | 3 | 6 | Low | Mitigate | Write Logging and Monitoring Policy (05) | Nov 2026 | Open |
| R-09 | No written incident reporting process, so response may be inconsistent | All | 17.3 | 2 | 3 | 6 | Low | Mitigate | Write a one-page incident reporting procedure | Dec 2026 | Open |
| R-10 | Git token stored in plain text in ~/.git-credentials | A-02 | 5.2 | 2 | 3 | 6 | Low | Accept | Accepted: fine-grained token limited to one repo with 90-day expiry; rotate before expiry | Feb 2027 | Accepted |
| R-11 | GitHub token exposed in a chat message | C-01 | 17.3 | 1 | 1 | 1 | Low | Mitigated | Exposed token revoked and replaced with a new token | Nov 2026 | Closed |
| R-12 | Host runs Windows 11 Home with no Group Policy Editor, limiting hardening | A-01 | 4.1 | 2 | 3 | 6 | Low | Accept | Accepted: upgrade cost not justified for a lab; apply settings manually where possible | Review Mar 2027 | Accepted |
| R-13 | 74 CIS checks invalid on Ubuntu under WSL, so assessment coverage is incomplete | A-02 | 4.1 | 3 | 2 | 6 | Low | Accept | Accepted: WSL limitation; documented in 02-sca-baseline.md | Review Mar 2027 | Accepted |

## Summary
| Rating | Count | Risks |
|--------|-------|-------|
| High | 2 | R-01, R-02 |
| Medium | 4 | R-03, R-04, R-05, R-06 |
| Low | 7 | R-07 to R-13 |

Treatment: 9 Mitigate, 3 Accept, 1 Closed.
Note: R-11 score shows residual risk after the token was revoked (original exposure rated L3 x I4 = 12, Medium).

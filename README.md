# SOC L1 Investigation Write-ups

Investigation write-ups from the open-source **Sentinel Desk SOC L1 lab** by sumitsaini-sec (https://github.com/sumitsaini-sec/SOC-L1-investigation-lab), run locally on Kali Linux. The lab uses synthetic data only. This repo contains my own analysis, not the lab's code.

## Investigations

| Alert | Summary | Verdict | Score |
|---|---|---|---|
| ALT3-00004 | msiexec.exe silently installed an invoice-named MSI from the Temp folder, then beaconed to sync-0.test every 113s (53 connections) | True Positive, escalated to L2 | 61/100 (attempt 1) |

## Method

I use the 5W framework (who, what, when, where, why), a 5-question triage check, and a per-alert evidence sweep covering process, network, identity, baseline context and IOC object records. See `triage-checklist.md`.

## Skills practiced

- SIEM querying
- Process-chain analysis
- Beaconing detection
- IOC enrichment
- Scoping and escalation writing
- MITRE ATT&CK mapping (T1218.007, T1071.001)

## Lessons learned

See `lessons-learned.md` for what I missed in attempt 1 and how I improved.

“Attempt 1 report contains unresolved placeholders and a response-log mix-up; see lessons-learned. Attempt 2 coming.”


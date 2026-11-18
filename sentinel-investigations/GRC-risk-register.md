# Home Lab Risk Register

I am a beginner learning governance, risk and compliance (GRC). This register is about my own home lab, one Windows Server called LAB-DC-01 in the domain labcorp.local. It is not a real company. I scored each risk myself, so the scores are my own judgement.

**How I scored.** Likelihood is 1 to 5 (1 is very unlikely, 5 is almost certain). Impact is 1 to 5 (1 is tiny harm, 5 is very serious harm). Score is Likelihood x Impact. 1 to 6 is Low, 7 to 12 is Medium, 13 to 25 is High.

**Status key.** Open means not started. In progress means partly done. Done means finished and tested.

## Register

| ID | Risk | Cause | What could happen | Likelihood | Impact | Score | Rating | Control I already have | Action | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R1 | Passwords can be guessed again and again | New domains start with account lockout switched off (set to 0) | An attacker takes over an account | 3 | 4 | 12 | Medium | Lockout set to 5 wrong tries in Group Policy (troubleshooting log, entry 05) | Type 5 wrong passwords and screenshot the account locking. Consider MFA in a real setup | Me | In progress |
| R2 | A new admin account is created without permission | An attacker or careless admin adds an account to Domain Admins | Full control of the whole domain | 3 | 5 | 15 | High | Sentinel searches for events 4720 and 4728, plus a runbook with escalation steps | Review the Domain Admins group once a month. Turn the search into an automatic alert | Me | Open |
| R3 | Logs stop arriving and I do not notice | The Azure Monitor Agent showed Succeeded but sent no data for about a day (log, entry 08) | An attack could happen with no record of it | 3 | 4 | 12 | Medium | Heartbeat search to check the agent is alive | Create an alert that fires when the heartbeat stops | Me | In progress |
| R4 | A phishing document runs commands on the server | A Word or Excel macro starts another program | Malware runs on the server | 2 | 4 | 8 | Medium | Sentinel search for Word or Excel starting other programs (event 4688). No results found | Test the search with a harmless fake macro to prove it works | Me | Open |
| R5 | Other devices can reach the server | The server shares a network with other devices if set up wrongly | An attacker reaches the server | 3 | 4 | 12 | Medium | Server moved to an Internal Network so it is isolated (log, entry 04) | Check Windows Firewall is switched on. I have not checked this yet | Me | Open |
| R6 | The server breaks and work is lost | The VM crashed and I rebuilt it from scratch (log, entries 01 and 03) | Lost time and lost settings | 4 | 3 | 12 | Medium | None yet | Take a VirtualBox snapshot after each big step. Check Windows updates | Me | Open |

## Standards key

| ID | ISO 27001:2022 Annex A | Cyber Essentials | Plain meaning |
|---|---|---|---|
| R1 | 8.5 Secure authentication | User access control | Make people prove who they are safely |
| R2 | 8.2 Privileged access rights | User access control | Control who gets admin power |
| R3 | 8.15 Logging, 8.16 Monitoring activities | No direct match | Keep records and watch them |
| R4 | 8.7 Protection against malware | Malware protection | Stop harmful software |
| R5 | 8.20 Networks security, 8.22 Segregation of networks | Firewalls | Keep networks separate and protected |
| R6 | 8.13 Information backup, 8.8 Management of technical vulnerabilities | Security update management | Keep copies and keep systems patched |

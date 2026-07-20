## File 1: `brute-force-success.md`

# Runbook: Brute Force Login Followed by Success

**The situation** An attacker is hammering an account with bad passwords, eventually guesses right, and gets active access. This is a high-priority alert because the bad guy is officially inside the perimeter.

---

## 1. Alert Trigger & Sentinel KQL Query
**Trigger Condition:** A single IP tries and fails to log in 10 or more times within 15 minutes against one account, and then successfully logs into that same account within the next 30 minutes.

### The KQL Blueprint
```kql
let TimeWindow = 45m;
let FailedThreshold = 10;
SecurityEvent
| where TimeGenerated > ago(TimeWindow)
| where EventID == 4625 // Failed Login
| summarize FailedCount = count() by Account, SourceIP = IpAddress, bin(TimeGenerated, 15m)
| where FailedCount >= FailedThreshold
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(TimeWindow)
    | where EventID == 4624 // Successful Login
    | where LogonType in (2, 3, 10) // Interactive, Network, or RDP
    | project TimeOfSuccess = TimeGenerated, Account, SourceIP = IpAddress, LogonType
) on Account, SourceIP
| where TimeOfSuccess > TimeGenerated
| project TimeOfSuccess, Account, SourceIP, FailedCount, LogonType

---

## 2. Triage Steps (Is it real?)

1. **Check the Attacker IP:** Drop the source IP into VirusTotal or AbuseIPDB. Is it a known bad actor, a random proxy, or a VPN exit node?
2. **Look at User History:** Check the user's normal baseline. Does this employee normally log in from this country or device? Look out for "impossible travel" (e.g., logging in from Edinburgh and then Tokyo 20 minutes later).
3. **Call it:**
 **True Positive:** The traffic comes from a sketchy IP followed by a weird login success. Move to containment immediately.
 **False Positive:** The user just locked themselves out because they forgot their caps lock was on at home, then finally got the password right. Close the alert.
---

## 3. Evidence to Collect (The Forensic Proof)

* **Event ID 4625:** Look for the failure codes to see why it failed (like wrong password).
* **Event ID 4624:** Check the `LogonType`. Type 3 means network access; Type 10 means they just RDP’d straight into the desktop.
* **Account Status:** Find out who this user is. Are they a regular employee, or do they have Domain Admin/Privileged rights?
* **Host Logs:** Check what happened immediately after the success timestamp. Look at Event ID 4688 to see if any weird processes (like PowerShell or command prompts) started spawning.

---

## 4. Escalation Criteria (When to ring the alarm)

Pass this up to Tier 2 / Incident Response Lead immediately if:

* The compromised account belongs to a Domain Admin, Executive, or crucial service account.
* You see immediate lateral movement (the attacker starts jumping to other servers or running admin tools within minutes of getting in).
* The IP ties back to a known Advanced Persistent Threat (APT) group or active ransomware actor.

---

## 5. Containment & Closure Notes

### Containment Actions

 **Kill the Session:** Forcefully reset the user's Active Directory / Entra ID password and revoke all active login sessions/tokens to kick the attacker out.
 **Block the IP:** Add a firewall rule to drop all incoming traffic from the attacker's source IP.
 **Fix MFA:** If MFA wasn't turned on, freeze the account until Multi-Factor Authentication is fully set up and verified.

### Closure

 Verify that the attacker didn't drop any backdoor accounts or scheduled tasks while they were in.
 Securely hand the account back to the user via a verified phone call or in-person check.

---

## 6. Regulatory Implication Flag

 **Data Breach Check:** If this account had access to databases with customer PII (Personally Identifiable Information), financial records, or HR data, flag this for the Data Protection Officer (DPO). Under regulations like GDPR, if sensitive data was exposed, the legal notification clock starts ticking.

---

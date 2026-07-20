# Runbook: New Local Administrator Account Created

**situation** A new account was suddenly granted local admin rights on a machine. Attackers love doing this for persistence so they can maintain full control over a system even if their initial web shell or malware gets deleted.

---

## 1. Alert Trigger & Sentinel KQL Query
**Trigger Condition:** Any event showing a user account being added to a local security-enabled administrative group.

### The KQL Blueprint
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4732 // A member was added to a security-enabled local group
| extend TargetGroup = TargetUserName
| where TargetGroup == "Administrators"
| project TimeGenerated, Computer, Account, SecurityID, MemberName = MemberUserName, TargetGroup

---

## 2. Triage Steps (Is it real?)

1. **Check Change Management:** Was there a scheduled ticket or IT maintenance task to create a new admin account on this specific machine today?
2. **Identify the Creator:** Look at the `Account` column to see *who* ran the command to create the admin. Was it a legitimate IT engineer, or was it a system process/compromised user?
3. **Check Machine Context:** Is this machine a critical server, a developer laptop, or an exposed web server? An unexpected admin on an internet-facing server is an immediate red flag.
4. **Call it:**
* **True Positive:** A random local admin was created without an IT ticket, especially out of hours. Treat this as an active system compromise.
* **False Positive:** A system administrator was doing authorized troubleshooting and forgot to log the ticket. Verify with them directly.

---

## 3. Evidence to Collect (The Forensic Proof)

**Event ID 4732:** Pinpoints the exact moment the user was added to the local Admin group.
**Event ID 4720:** Check if a brand-new user account was created right before it was made an admin.
**Event ID 4688 (Process Creation):** Look back 15 minutes before the account was created. Look for commands like `net user /add` or `net localgroup administrators`. This tells you exactly what tool or script the attacker used.
**Parent Process Analysis:** Check *what* launched the command. If the parent process is a web server service (like Apache or IIS), you are dealing with a web shell exploitation.

---

## 4. Escalation Criteria (When to ring the alarm)

Pass this up to Tier 2 / Incident Response Lead immediately if:

* The account that created the new admin is a standard user account (meaning they likely escalated privileges illegally).
* The new admin account was created on a Domain Controller or a critical database server.
* You see immediate follow-up actions, like the new admin account turning off Windows Defender or clearing security event logs.

---

## 5. Containment & Closure Notes

### Containment Actions

**Isolate the Host:** Use your EDR tool (like Defender for Endpoint) to isolate the compromised computer from the network so it can't talk to other machines.
**Nuke the Account:** Immediately remove the rogue account from the local Administrators group and disable the account entirely.
**Kill the Creator Session:** If a compromised user account was used to create the admin, reset that user's password and terminate their active sessions immediately.

### Closure

* Conduct a full malware and web directory scan on the isolated machine to find out how the attacker got the access needed to run admin commands in the first place.
* Re-image the machine if the root cause of the initial access cannot be confidently identified and eradicated.

---

## 6. Regulatory Implication Flag

* **Compliance Check:** Unauthorizied privilege escalation on a network endpoint violates internal access control policies (like ISO 27001 or Cyber Essentials). Flag this to the compliance or security audit team to log the unauthorized internal control failure.

# Security Incident Case File: Unauthorized Privileged Account Creation

## Executive Summary
* **Incident:** New privileged user account created.
* **Detection Source:** Windows Security EventID 4720 and 4728.
* **MITRE ATT&CK Technique:** T1136.001 (Create Account: Local Account)

---

## Technical Details: What Happened?
During routine security log analysis on the domain controller (`LAB-DC-01`), a new user account was detected as being created and immediately escalated to highly privileged administrative groups within a brief window. 

* **Target Account Name:** badactor
* **Creation Timestamp:** 22/06/2026 13:32:28
* **Creation Action Entity (SubjectUserName):** Administrator

Immediately following creation, this new entity was appended to the `Domain Admins` global security group, granting unrestricted administrative capabilities across the domain environment.

---

## Analysis & Impact Assessment

### Why This Matters
Unauthorized creation of privileged accounts is a critical indicator of compromise (IoC). Attackers frequently leverage this persistence technique post-compromise to maintain access to the infrastructure even if their initial entry vector is discovered and mitigated.

### Regulatory Note
If an event of this nature occurred within a production environment processing personal data, any unauthorized data access executed by this account would require comprehensive tracking and reporting under **GDPR audit compliance frameworks**. Failure to document and declare unauthorized structural processing accounts can lead to severe regulatory penalties.

---

## Incident Response: Recommended Action
1. **Verification:** Cross-reference the timestamp with internal IT change control tickets to determine if this was an authorized, planned deployment.
2. **Immediate Containment:** If the creation is unplanned or unverified, immediately **disable** the `badactor` account to stop active exploitation.
3. **Evidence Preservation:** Isolate and preserve the Windows Security Event Log (`.evtx`) containing Event IDs 4720 and 4728 for forensic analysis.
4. **Escalation:** Escalate the incident ticket immediately to Tier 2/Incident Response handlers for deeper timeline analysis.

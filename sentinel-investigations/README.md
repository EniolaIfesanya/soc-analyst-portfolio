# SOC Analyst Shift Report: Threat Hunting & Telemetry Verification
**Author:** Eniola Ifesanya  
**Assigned Workspace:** `law-cyber-portfolio`  
**Data Stream Source:** `LAB-DC-01` (Windows Server 2022 Domain Controller via Azure Arc/AMA)  
**Shift Date:** 09 July 2026  

---

## 1. Shift Overview
During this shift, proactive threat-hunting operations were executed against the primary Domain Controller (`LAB-DC-01`) telemetry stream inside Microsoft Sentinel. The objective was to validate the newly engineered log pipeline and hunt for specific indicators of compromise (IoCs) across three core attack vectors: Identity Brute-Forcing, Malicious Phishing Execution, and Persistence Mechanisms. 

All core pipeline infrastructure is verified stable, and live telemetry ingestion is fully functional.

---

## 2. Threat Hunting Investigations & Query Breakdown

### Hunt 1: Identity Brute-Force Monitoring (Credential Access)
* **The Objective:** Detect unauthorized or anomalous authentication failures targeting administrative domain accounts.
* **The KQL Query:**
  ```kql
  SecurityEvent
  | where EventID == 4625
  | summarize FailedLogins = count() by Account
  | order by FailedLogins desc
The Result: 1 Target Account Identified (LABCORP\Administrator / Count: 2).

Analyst Context & Meaning: The hunt successfully surfaced two explicit authentication failures matching Windows Event ID 4625. Cross-referencing these logs with internal lab test schedules confirms these events were generated during planned bad-password telemetry validation testing. Because the threshold did not cross critical limits and the origin was internal, this is classified as an intentional baseline test rather than an active external brute-force campaign.

### Hunt 2: Spear-Phishing Macro Execution (Execution / Initial Access)
The Objective: Monitor whether productivity software (Microsoft Word/Excel) is being manipulated to spawn unauthorized background command shells or administrative tools.

The KQL Query:

SecurityEvent
| where EventID == 4688
| where ParentProcessName has "winword.exe" or ParentProcessName has "excel.exe"
| project TimeGenerated, Account, ParentProcessName, NewProcessName, CommandLine
The Result: No results found from the last 24 hours.

Analyst Context & Meaning: In a live SOC shift, a null result on this query represents a healthy, verified security baseline. It confirms that no phishing documents containing malicious macros have successfully bypassed basic defenses to execute downstream child processes within the monitored server environment during the observation window.

### Hunt 3: Unauthorized Account Persistence (Persistence)
The Objective: Audit the environment for stealthy account creations or unauthorized escalations into privileged security groups (e.g., Domain Admins).

The KQL Query:

SecurityEvent
| where EventID in (4720, 4728)
| project TimeGenerated, SubjectUserName, TargetUserName, MemberName
| order by TimeGenerated desc
The Result: No results found.

Analyst Context & Meaning: This query targeted Event IDs 4720 (User Creation) and 4728 (Global Group Additions). The lack of returned records indicates zero configuration changes to the domain infrastructure during this operational window. No rogue accounts were introduced, verifying that the current Active Directory directory structure remains securely aligned with the established administrative baseline.

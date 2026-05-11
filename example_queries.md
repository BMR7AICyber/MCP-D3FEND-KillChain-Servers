# Example Queries — Cyber Defense MCP Suite
# ============================================
# Use these directly in Claude Desktop after installing both servers.
# Each block is a ready-to-paste prompt for SOC workflows.


## ── D3FEND SERVER EXAMPLES ──────────────────────────────────────────────────


### 1. Map ATT&CK technique to defensive countermeasures
"""
I just got an alert for T1059 (Command and Scripting Interpreter) on one of our endpoints.
Use D3FEND to show me what defensive countermeasures exist for this technique.
"""

### 2. PowerShell-specific sub-technique
"""
Our EDR flagged T1059.001 (PowerShell). What D3FEND countermeasures specifically address 
PowerShell abuse? Show technique details for the top result.
"""

### 3. Credential-based attack coverage
"""
We had a T1003.001 (LSASS Memory dump) incident last week.
Get the D3FEND countermeasures for T1003 and assess whether our current defenses 
(D3-PAN, D3-CH, D3-EHB) leave any gaps.
"""

### 4. Search by artifact type for detection coverage
"""
Our network team wants to improve monitoring of Network Traffic artifacts.
Use D3FEND to find all defensive techniques that protect or analyze network traffic.
"""

### 5. Phishing delivery artifact coverage
"""
We're evaluating our email security posture. Search D3FEND for techniques 
that protect Email artifacts and tell me what we might be missing.
"""

### 6. Gap analysis for an SOC's current defensive stack
"""
Our current deployed D3FEND techniques are:
['D3-PAN', 'D3-NTF', 'D3-PA', 'D3-EHB', 'D3-CH']

Run a coverage gap analysis and tell me which D3FEND tactic categories 
we're missing coverage in, and what our current defensive posture rating is.
"""

### 7. Get the full D3FEND matrix
"""
Pull the full D3FEND defensive matrix resource and give me a summary of 
all tactic categories and how many techniques exist in each.
"""

### 8. Deep dive on a specific technique
"""
Get the full details for D3FEND technique D3-PAN (Process Ancestry Analysis).
What ATT&CK techniques does it counter, and are there KB references I should review?
"""


## ── KILL CHAIN SERVER EXAMPLES ──────────────────────────────────────────────


### 9. Single-event IOC analysis (Delivery stage)
"""
My SOC received these alerts in the last hour:
- "spear phishing email detected with malicious attachment"
- "password protected zip file downloaded"
- "suspicious macro execution attempt blocked"

Which kill chain stage does this activity map to? What should my SOC do right now?
"""

### 10. C2 detection and triage
"""
We're seeing these network behaviors from a host:
["dns tunneling", "periodic callback every 60 seconds", "base64 encoded traffic", 
 "non-standard port 8443", "abnormal user agent", "domain fronting detected"]

Analyze the kill chain stage and give me the full defensive controls playbook for it.
"""

### 11. Get full defensive controls for Exploitation stage
"""
After a successful phishing attack, I want to understand all the defensive controls 
available for the Exploitation stage of the kill chain. Give me the complete playbook 
including detection opportunities.
"""

### 12. Map ATT&CK tactic to Kill Chain stage
"""
Our threat intel team flagged activity matching MITRE tactic TA0011.
Map this to the kill chain stage and tell me what comes next so I can hunt proactively.
"""

### 13. Multi-event attack progression tracking (Full incident scenario)
"""
Track the progression of this attack through the kill chain:

Events:
1. 2024-01-20T08:15:00Z — ["nmap port scan", "shodan enumeration of our IP range"]
2. 2024-01-20T09:30:00Z — ["spear phishing email", "malicious attachment with VBA macro"]  
3. 2024-01-20T10:45:00Z — ["macro execution", "powershell execution", "process injection"]
4. 2024-01-20T11:00:00Z — ["registry run key added", "new scheduled task created", "service install"]
5. 2024-01-20T11:30:00Z — ["cobalt strike beacon", "c2 beaconing", "dns tunneling"]
6. 2024-01-20T13:00:00Z — ["vssadmin delete shadows", "file encryption", "large data exfil"]

Tell me: How far has the attacker progressed? What stage are they at now? 
What immediate actions should my IR team take?
"""

### 14. Ransomware IOC triage
"""
We have IOCs consistent with a ransomware incident:
["lockbit ransomware", "vssadmin delete shadows", "ntds.dit access", 
 "lateral movement via pass the hash", "backup deletion", "file encryption at scale"]

Identify the kill chain stage(s) and give me prioritized response actions.
"""

### 15. Pull the complete kill chain framework
"""
Give me the complete Cyber Kill Chain framework resource — all 7 stages, 
their MITRE ATT&CK mappings, and top IOC patterns for each stage.
"""

### 16. Combined workflow (both servers together)
"""
We detected T1071.001 (Web Protocols C2) on a host. 

Step 1: Map this ATT&CK tactic to its kill chain stage using the kill chain server.
Step 2: Get the defensive controls for that kill chain stage.
Step 3: Use D3FEND to get countermeasures for T1071 and check our gap coverage 
        with deployed techniques ['D3-NTA', 'D3-NTF', 'D3-PAN'].

Give me a consolidated SOC playbook response.
"""

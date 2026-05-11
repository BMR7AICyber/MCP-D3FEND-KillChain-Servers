"""
Cyber Kill Chain MCP Server — Production Grade
Lockheed Martin Kill Chain analysis for SOC threat intelligence workflows.
Author: Built for cybersecurity AI integration
"""

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("killchain-mcp")

MAX_INPUT_ITEMS = 200
MAX_STRING_LEN  = 512

# ─────────────────────────────────────────────
# Kill Chain Knowledge Base
# ─────────────────────────────────────────────
KILL_CHAIN_STAGES: dict[str, dict] = {
    "reconnaissance": {
        "stage_number":   1,
        "name":           "Reconnaissance",
        "description":    "Adversary researches, identifies, and selects targets. Includes passive and active intelligence gathering.",
        "objective":      "Understand the target environment before launching an attack.",
        "mitre_tactics":  ["TA0043"],
        "mitre_tactics_names": ["Reconnaissance"],
        "ioc_patterns": [
            "port scan", "nmap", "shodan", "whois", "dns enumeration",
            "linkedin scraping", "job posting analysis", "wayback machine",
            "certificate transparency", "passive dns", "osint", "recon-ng",
            "theHarvester", "maltego", "spiderfoot", "zone transfer",
            "subdomain enumeration", "email harvesting",
        ],
        "defensive_controls": [
            "Reduce public attack surface (minimize exposed services)",
            "Monitor and alert on unusual DNS queries / zone transfer attempts",
            "Implement web application firewalls with bot detection",
            "Restrict employee information visible on public platforms",
            "Deploy honeypots and canary tokens to detect reconnaissance",
            "Enable Certificate Transparency log monitoring",
            "Monitor Shodan and similar services for your IP ranges",
            "Use WHOIS privacy protection for domain registrations",
        ],
        "detection_opportunities": [
            "Web server access log anomalies (scanner signatures)",
            "Multiple failed authentication attempts from external IPs",
            "Unusual volume of DNS queries",
            "Alert on port scanning signatures in IDS/IPS",
        ],
        "soc_priority": "MEDIUM",
    },

    "weaponization": {
        "stage_number":   2,
        "name":           "Weaponization",
        "description":    "Adversary couples a remote access trojan with an exploit into a deliverable payload (weaponizer).",
        "objective":      "Create a functional exploit package tailored to target vulnerabilities.",
        "mitre_tactics":  ["TA0001"],
        "mitre_tactics_names": ["Resource Development"],
        "ioc_patterns": [
            "exploit kit", "msfvenom", "cobalt strike", "metasploit",
            "shellcode", "obfuscated payload", "packed executable",
            "macro embedded", "VBA macro", "malicious office document",
            "CVE exploit", "zero-day", "exploit framework", "empire",
            "meterpreter", "payload crafting", "dropper", "stager",
        ],
        "defensive_controls": [
            "Maintain vulnerability management and patch cadence",
            "Subscribe to threat intelligence feeds for new CVE weaponization",
            "Deploy endpoint protection with exploit prevention capabilities",
            "Implement application whitelisting on critical systems",
            "Use sandboxed detonation for email attachments / downloads",
            "Monitor for known malware builder signatures (Yara rules)",
        ],
        "detection_opportunities": [
            "Difficult to detect (occurs off-network)",
            "Threat intel feeds may surface new exploit kits",
            "Monitor paste sites and dark web for weaponized exploits targeting your stack",
        ],
        "soc_priority": "LOW",
    },

    "delivery": {
        "stage_number":   3,
        "name":           "Delivery",
        "description":    "Adversary transmits the weapon to the target environment via chosen delivery vector.",
        "objective":      "Transport the weaponized payload into the target's perimeter.",
        "mitre_tactics":  ["TA0001"],
        "mitre_tactics_names": ["Initial Access"],
        "ioc_patterns": [
            "phishing email", "spear phishing", "malicious attachment",
            "malicious link", "drive-by download", "watering hole",
            "usb drop", "supply chain", "malicious macro", "html smuggling",
            "malvertising", "typosquatting", "credential harvesting page",
            ".lnk file", "iso mount", "zip attachment", "password protected archive",
            "qr code phish", "callback phishing",
        ],
        "defensive_controls": [
            "Deploy email security gateway with sandboxed attachment detonation",
            "Block high-risk attachment types at email gateway (.lnk, .iso, .vbs, .hta)",
            "Implement DMARC, DKIM, SPF email authentication",
            "Use DNS filtering / secure web gateway for malicious URLs",
            "Security awareness training focused on phishing recognition",
            "Disable autorun for removable media",
            "Implement web proxy with SSL inspection",
            "Block macro execution in Office documents from internet",
        ],
        "detection_opportunities": [
            "Email gateway alerts on suspicious attachments/links",
            "DNS query anomalies for newly registered domains",
            "Proxy logs for connections to typosquatted domains",
            "Endpoint alert on suspicious file types in email folders",
        ],
        "soc_priority": "HIGH",
    },

    "exploitation": {
        "stage_number":   4,
        "name":           "Exploitation",
        "description":    "The weapon's code executes, exploiting a vulnerability in the target application, OS, or user.",
        "objective":      "Trigger the exploit to gain initial code execution on the target.",
        "mitre_tactics":  ["TA0002"],
        "mitre_tactics_names": ["Execution"],
        "ioc_patterns": [
            "exploit", "buffer overflow", "use after free", "heap spray",
            "ROP chain", "privilege escalation", "dll injection",
            "process injection", "shellcode execution", "code execution",
            "CVE", "zero-day exploitation", "memory corruption", "type confusion",
            "java deserialization", "log4shell", "proxyshell", "eternalblue",
            "lateral movement", "credential dumping", "lsass dump",
        ],
        "defensive_controls": [
            "Enable DEP, ASLR, CFG on all endpoints",
            "Deploy EDR with exploit prevention and behavioral detection",
            "Patch management — prioritize internet-facing services",
            "Enable Exploit Guard / Attack Surface Reduction rules",
            "Restrict PowerShell execution policy (Constrained Language Mode)",
            "Implement Just-In-Time and Just-Enough access",
            "Enable Credential Guard to protect LSASS",
            "Use application sandboxing for browser and email clients",
        ],
        "detection_opportunities": [
            "EDR alerts on process injection / unusual parent-child process trees",
            "LSASS access attempts from non-system processes",
            "PowerShell / WMI execution logging (Script Block Logging)",
            "Sysmon Event IDs 1, 8, 10 for process creation/injection",
            "Memory anomaly detection in EDR",
        ],
        "soc_priority": "CRITICAL",
    },

    "installation": {
        "stage_number":   5,
        "name":           "Installation",
        "description":    "Adversary installs a remote access trojan or backdoor to maintain persistent access.",
        "objective":      "Establish persistent foothold that survives reboots and detection attempts.",
        "mitre_tactics":  ["TA0003"],
        "mitre_tactics_names": ["Persistence"],
        "ioc_patterns": [
            "persistence", "registry run key", "scheduled task", "cron job",
            "service install", "dll hijacking", "bootkit", "rootkit",
            "startup folder", "wmi subscription", "autorun", "at job",
            "web shell", "backdoor install", "rat installed", "c2 beacon",
            "new service created", "registry modification", "lnk persistence",
            "image file execution options", "accessibility features hijack",
        ],
        "defensive_controls": [
            "Monitor and alert on new scheduled tasks, services, registry run keys",
            "Deploy FIM (File Integrity Monitoring) on critical directories",
            "Restrict write access to sensitive registry keys",
            "Implement application control to block unauthorized executables",
            "Alert on web shell signatures in web server directories",
            "Enable WMI activity logging and alert on new subscriptions",
            "Use privileged access workstations (PAWs) for admin tasks",
            "Network segmentation to contain lateral movement",
        ],
        "detection_opportunities": [
            "Sysmon Event ID 12/13 (Registry modification)",
            "Windows Event ID 4698 (Scheduled task created)",
            "Windows Event ID 7045 (New service installed)",
            "FIM alerts on system directory changes",
            "EDR behavioral detection on persistence mechanisms",
        ],
        "soc_priority": "CRITICAL",
    },

    "command_and_control": {
        "stage_number":   6,
        "name":           "Command & Control (C2)",
        "description":    "Adversary establishes a covert command channel to remotely control the implant inside the victim network.",
        "objective":      "Maintain reliable, covert communication with compromised hosts.",
        "mitre_tactics":  ["TA0011"],
        "mitre_tactics_names": ["Command and Control"],
        "ioc_patterns": [
            "beaconing", "c2", "command and control", "cobalt strike beacon",
            "dns tunneling", "http c2", "https c2", "domain generation algorithm",
            "dga", "fast flux", "domain fronting", "tor exit node",
            "unusual outbound traffic", "long connection", "periodic callback",
            "icmp tunnel", "covert channel", "encoded communication",
            "base64 encoded traffic", "abnormal user agent", "non-standard port",
            "c2 framework", "sliver", "havoc", "brute ratel",
        ],
        "defensive_controls": [
            "Deploy network traffic analysis (NTA) with ML-based anomaly detection",
            "Implement DNS sinkholing for known malicious domains",
            "Block or inspect outbound traffic to unexpected countries/ASNs",
            "Use SSL/TLS inspection proxy to analyze encrypted C2 traffic",
            "Block DNS-over-HTTPS (DoH) to unauthorized resolvers",
            "Implement network segmentation and egress filtering",
            "Alert on periodic beaconing patterns (Jitter analysis)",
            "Maintain IOC feeds and block known C2 infrastructure",
            "Use threat intel to identify domain fronting abuse",
        ],
        "detection_opportunities": [
            "Long connections to external IPs on non-standard ports",
            "Regular beaconing intervals detected by NTA tools",
            "DNS queries for algorithmically generated domains (DGA detection)",
            "Large outbound data transfers at unusual hours",
            "TLS certificate anomalies (self-signed, unusual CN fields)",
            "Zeek / Suricata / Snort rules for C2 signatures",
        ],
        "soc_priority": "CRITICAL",
    },

    "actions_on_objectives": {
        "stage_number":   7,
        "name":           "Actions on Objectives",
        "description":    "Adversary achieves their mission: data exfiltration, ransomware deployment, destruction, or further movement.",
        "objective":      "Accomplish the primary attack goal (data theft, disruption, espionage, financial gain).",
        "mitre_tactics":  ["TA0009", "TA0010", "TA0040"],
        "mitre_tactics_names": ["Collection", "Exfiltration", "Impact"],
        "ioc_patterns": [
            "data exfiltration", "exfil", "large upload", "ransomware",
            "file encryption", "wiper", "vssadmin delete shadows",
            "lateral movement", "domain controller compromise", "ntds.dit",
            "credential dump", "kerberoasting", "pass the hash",
            "sensitive data access", "database dump", "backup deletion",
            "destructive malware", "notpetya", "lockbit", "conti",
            "cloudstorage upload", "mega.nz", "ftp exfil", "dns exfil",
        ],
        "defensive_controls": [
            "Implement Data Loss Prevention (DLP) on endpoints and network",
            "Monitor for access to sensitive data stores (UEBA)",
            "Immutable backups (3-2-1 rule) stored offline / air-gapped",
            "Privileged Account Management — restrict domain admin scope",
            "Network-based DLP to detect large data transfers to external IPs",
            "Alert on VSS deletion, encryption at scale, or backup tool execution",
            "Segment crown jewel assets and restrict access",
            "Implement Just-In-Time access to sensitive systems",
        ],
        "detection_opportunities": [
            "Large outbound data transfers to cloud storage / external IPs",
            "VSS deletion events (Windows Event ID 524)",
            "Rapid file extension changes (ransomware indicator)",
            "UEBA alert on unusual access to sensitive file shares",
            "NTDS.dit or SAM database access attempts",
            "Lateral movement indicators (pass-the-hash, Kerberos ticket anomalies)",
        ],
        "soc_priority": "CRITICAL",
    },
}

# ATT&CK Tactic → Kill Chain Stage mapping
MITRE_TACTIC_TO_STAGE: dict[str, str] = {
    # TA IDs
    "TA0043": "reconnaissance",
    "TA0042": "weaponization",
    "TA0001": "delivery",
    "TA0002": "exploitation",
    "TA0003": "installation",
    "TA0005": "installation",      # Defense Evasion often pairs with Installation
    "TA0004": "exploitation",      # Privilege Escalation
    "TA0006": "exploitation",      # Credential Access
    "TA0007": "reconnaissance",    # Discovery (post-compromise recon)
    "TA0008": "actions_on_objectives",  # Lateral Movement
    "TA0009": "actions_on_objectives",  # Collection
    "TA0011": "command_and_control",
    "TA0010": "actions_on_objectives",  # Exfiltration
    "TA0040": "actions_on_objectives",  # Impact

    # Common name variants (lowercase)
    "reconnaissance":       "reconnaissance",
    "resource development": "weaponization",
    "initial access":       "delivery",
    "execution":            "exploitation",
    "persistence":          "installation",
    "privilege escalation": "exploitation",
    "defense evasion":      "installation",
    "credential access":    "exploitation",
    "discovery":            "reconnaissance",
    "lateral movement":     "actions_on_objectives",
    "collection":           "actions_on_objectives",
    "command and control":  "command_and_control",
    "c2":                   "command_and_control",
    "exfiltration":         "actions_on_objectives",
    "impact":               "actions_on_objectives",
}

STAGE_ORDER = [
    "reconnaissance", "weaponization", "delivery", "exploitation",
    "installation", "command_and_control", "actions_on_objectives",
]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def _envelope(tool: str, status: str, data: Any, meta: dict | None = None) -> dict:
    return {
        "schema_version": "1.0",
        "tool":           tool,
        "status":         status,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "data":           data,
        "meta":           meta or {},
    }


def _score_stage(indicators: list[str], stage_key: str) -> int:
    """Count how many IOC patterns from a stage match any indicator."""
    patterns = KILL_CHAIN_STAGES[stage_key]["ioc_patterns"]
    indicator_blob = " ".join(i.lower() for i in indicators)
    return sum(1 for p in patterns if p.lower() in indicator_blob)


def _sanitize_string(s: str) -> str:
    """Basic input sanitization."""
    return s[:MAX_STRING_LEN].strip()


# ─────────────────────────────────────────────
# FastMCP Server
# ─────────────────────────────────────────────
mcp = FastMCP(
    "Cyber Kill Chain Intelligence",
    instructions=(
        "Analyzes attack indicators against the Lockheed Martin Cyber Kill Chain framework. "
        "Use analyze_attack_stage() to identify which kill chain phase an attack is in, "
        "get_defensive_controls() for stage-specific countermeasures, and "
        "track_attack_progression() to understand threat actor movement across all 7 stages."
    ),
)


# ─────────────────────────────────────────────
# Tool 1 — analyze_attack_stage
# ─────────────────────────────────────────────
@mcp.tool()
async def analyze_attack_stage(observed_indicators: list[str]) -> dict:
    """
    Analyze observed Indicators of Compromise (IOCs) or behavioral indicators
    and identify which Cyber Kill Chain stage(s) they map to.

    Args:
        observed_indicators: List of IOC strings or attack behaviors observed
                             (e.g. ['dns tunneling', 'c2 beaconing', 'periodic callback'])

    Returns:
        Ranked kill chain stages with confidence scores, matched IOC patterns,
        and analyst recommendations.
    """
    if not observed_indicators:
        return _envelope("analyze_attack_stage", "error", None,
                         {"error": "observed_indicators cannot be empty"})
    if len(observed_indicators) > MAX_INPUT_ITEMS:
        return _envelope("analyze_attack_stage", "error", None,
                         {"error": f"Too many indicators (max {MAX_INPUT_ITEMS})"})

    sanitized = [_sanitize_string(str(i)) for i in observed_indicators]

    # Score all stages
    scores: dict[str, int] = {}
    matched_patterns: dict[str, list[str]] = {}
    for stage_key, stage_data in KILL_CHAIN_STAGES.items():
        indicator_blob = " ".join(s.lower() for s in sanitized)
        matched = [p for p in stage_data["ioc_patterns"] if p.lower() in indicator_blob]
        scores[stage_key]          = len(matched)
        matched_patterns[stage_key] = matched

    # Rank by score
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_stage_key   = ranked[0][0]
    top_score       = ranked[0][1]
    total_indicators = len(sanitized)

    # Confidence levels
    def confidence(score: int) -> str:
        if score == 0:       return "NONE"
        if score == 1:       return "LOW"
        if score <= 3:       return "MEDIUM"
        if score <= 6:       return "HIGH"
        return "VERY HIGH"

    stage_results = []
    for stage_key, score in ranked:
        if score == 0:
            continue
        stage = KILL_CHAIN_STAGES[stage_key]
        stage_results.append({
            "stage_number":      stage["stage_number"],
            "stage":             stage_key,
            "name":              stage["name"],
            "score":             score,
            "confidence":        confidence(score),
            "matched_patterns":  matched_patterns[stage_key],
            "soc_priority":      stage["soc_priority"],
        })

    if not stage_results:
        return _envelope("analyze_attack_stage", "no_match",
                         {"indicators_analyzed": sanitized,
                          "message": "No kill chain patterns matched. Review indicator specificity."},
                         {"tip": "Try including tool names, network behaviors, or file activities"})

    primary = KILL_CHAIN_STAGES[top_stage_key]
    result = _envelope(
        "analyze_attack_stage",
        "success",
        {
            "primary_stage":     {
                "stage_number":  primary["stage_number"],
                "stage":         top_stage_key,
                "name":          primary["name"],
                "confidence":    confidence(top_score),
                "description":   primary["description"],
                "soc_priority":  primary["soc_priority"],
            },
            "all_matched_stages":  stage_results,
            "indicators_analyzed": sanitized,
            "analyst_note":        (
                f"Attack activity most consistent with Stage {primary['stage_number']}: "
                f"{primary['name']}. "
                f"{'Consider investigating adjacent stages for progression.' if len(stage_results) > 1 else ''}"
            ),
        },
        {"matched_stage_count": len(stage_results)},
    )
    logger.info("analyze_attack_stage: %d indicators → primary=%s (%s)",
                total_indicators, top_stage_key, confidence(top_score))
    return result


# ─────────────────────────────────────────────
# Tool 2 — get_defensive_controls
# ─────────────────────────────────────────────
@mcp.tool()
async def get_defensive_controls(stage: str) -> dict:
    """
    Retrieve specific defensive controls, detection opportunities, and
    MITRE ATT&CK tactic mappings for a given kill chain stage.

    Args:
        stage: Kill chain stage name. One of:
               reconnaissance | weaponization | delivery | exploitation |
               installation | command_and_control | actions_on_objectives

    Returns:
        Full defensive playbook for the stage including controls,
        detection opportunities, and SOC priority level.
    """
    stage_key = stage.lower().strip().replace(" ", "_").replace("-", "_")
    # Handle common aliases
    aliases = {
        "c2": "command_and_control",
        "command and control": "command_and_control",
        "actions on objectives": "actions_on_objectives",
        "action on objective": "actions_on_objectives",
    }
    stage_key = aliases.get(stage_key, stage_key)

    if stage_key not in KILL_CHAIN_STAGES:
        valid = list(KILL_CHAIN_STAGES.keys())
        return _envelope("get_defensive_controls", "error", None, {
            "error": f"Unknown stage: {stage!r}",
            "valid_stages": valid,
        })

    s = KILL_CHAIN_STAGES[stage_key]
    result = _envelope(
        "get_defensive_controls",
        "success",
        {
            "stage_number":           s["stage_number"],
            "stage":                  stage_key,
            "name":                   s["name"],
            "description":            s["description"],
            "objective":              s["objective"],
            "soc_priority":           s["soc_priority"],
            "mitre_tactics":          s["mitre_tactics"],
            "mitre_tactics_names":    s["mitre_tactics_names"],
            "defensive_controls":     s["defensive_controls"],
            "detection_opportunities": s["detection_opportunities"],
            "common_ioc_patterns":    s["ioc_patterns"][:10],  # Top 10 for readability
        },
    )
    logger.info("get_defensive_controls: %s", stage_key)
    return result


# ─────────────────────────────────────────────
# Tool 3 — map_mitre_to_killchain
# ─────────────────────────────────────────────
@mcp.tool()
async def map_mitre_to_killchain(attack_tactic: str) -> dict:
    """
    Map a MITRE ATT&CK tactic (name or TA ID) to its corresponding
    Cyber Kill Chain stage.

    Args:
        attack_tactic: ATT&CK tactic ID or name
                       (e.g. 'TA0011', 'Command and Control', 'Exfiltration', 'Persistence')

    Returns:
        Mapped kill chain stage with stage details and bi-directional relationship context.
    """
    tactic_clean = _sanitize_string(attack_tactic).strip()
    lookup_key   = tactic_clean.lower().strip()

    stage_key = MITRE_TACTIC_TO_STAGE.get(lookup_key) or \
                MITRE_TACTIC_TO_STAGE.get(tactic_clean.upper())

    if not stage_key:
        # Fuzzy match attempt
        for k, v in MITRE_TACTIC_TO_STAGE.items():
            if lookup_key in k or k in lookup_key:
                stage_key = v
                break

    if not stage_key:
        return _envelope("map_mitre_to_killchain", "not_found", {
            "attack_tactic": tactic_clean,
            "message": "No direct kill chain mapping found for this tactic.",
            "supported_tactics": list(MITRE_TACTIC_TO_STAGE.keys()),
        })

    s = KILL_CHAIN_STAGES[stage_key]
    # Adjacent stages for context
    idx = STAGE_ORDER.index(stage_key)
    prev_stage = STAGE_ORDER[idx - 1] if idx > 0 else None
    next_stage = STAGE_ORDER[idx + 1] if idx < len(STAGE_ORDER) - 1 else None

    result = _envelope(
        "map_mitre_to_killchain",
        "success",
        {
            "attack_tactic":   tactic_clean,
            "kill_chain_stage": {
                "stage_number": s["stage_number"],
                "stage":        stage_key,
                "name":         s["name"],
                "description":  s["description"],
                "soc_priority": s["soc_priority"],
            },
            "stage_context": {
                "previous_stage": prev_stage,
                "current_stage":  stage_key,
                "next_stage":     next_stage,
            },
            "mitre_attack_url": f"https://attack.mitre.org/tactics/{tactic_clean.upper()}/",
        },
    )
    logger.info("map_mitre_to_killchain: %s → %s", tactic_clean, stage_key)
    return result


# ─────────────────────────────────────────────
# Tool 4 — track_attack_progression
# ─────────────────────────────────────────────
@mcp.tool()
async def track_attack_progression(events: list[dict]) -> dict:
    """
    Analyze a sequence of attack events and track adversary progression
    through the 7 kill chain stages. Identifies how far the attacker has advanced.

    Args:
        events: List of event dicts, each with at minimum:
                - 'timestamp': ISO 8601 string (e.g. '2024-01-15T14:32:00Z')
                - 'indicators': List of IOC/behavior strings observed in that event

                Optional fields: 'source_ip', 'hostname', 'event_id'

    Returns:
        Kill chain progression timeline, attacker's current estimated stage,
        dwell time analysis, and prioritized response actions.

    Example:
        events = [
          {"timestamp": "2024-01-15T10:00:00Z", "indicators": ["port scan", "nmap"]},
          {"timestamp": "2024-01-15T14:00:00Z", "indicators": ["phishing email", "malicious attachment"]},
          {"timestamp": "2024-01-15T15:30:00Z", "indicators": ["c2 beaconing", "dns tunneling"]}
        ]
    """
    if not events:
        return _envelope("track_attack_progression", "error", None,
                         {"error": "events list cannot be empty"})
    if len(events) > MAX_INPUT_ITEMS:
        return _envelope("track_attack_progression", "error", None,
                         {"error": f"Too many events (max {MAX_INPUT_ITEMS})"})

    # Initialize stage activity tracker
    stage_activity: dict[str, list[str]] = {s: [] for s in STAGE_ORDER}
    timeline: list[dict] = []

    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        ts         = str(event.get("timestamp", f"event_{idx+1}"))[:64]
        indicators = [_sanitize_string(str(i)) for i in event.get("indicators", [])]
        if not indicators:
            continue

        # Score this event across all stages
        event_scores = {s: _score_stage(indicators, s) for s in STAGE_ORDER}
        best_stage = max(event_scores.items(), key=lambda item: item[1])[0]
        best_score = event_scores[best_stage]

        if best_score > 0:
            stage_activity[best_stage].extend(indicators)
            timeline.append({
                "event_index":    idx + 1,
                "timestamp":      ts,
                "mapped_stage":   best_stage,
                "stage_name":     KILL_CHAIN_STAGES[best_stage]["name"],
                "stage_number":   KILL_CHAIN_STAGES[best_stage]["stage_number"],
                "confidence":     "HIGH" if best_score >= 3 else "MEDIUM" if best_score >= 1 else "LOW",
                "indicators":     indicators[:10],
                "source_ip":      str(event.get("source_ip", ""))[:64],
                "hostname":       str(event.get("hostname", ""))[:64],
            })

    # Determine highest stage reached
    reached_stages = [s for s in STAGE_ORDER if stage_activity[s]]
    highest_stage  = reached_stages[-1] if reached_stages else None

    if not reached_stages:
        return _envelope("track_attack_progression", "no_match",
                     {"message": "Could not map any events to kill chain stages.",
                      "events_analyzed": len(events)})

    # Ensure highest_stage is not None (type guard for static analysis)
    assert highest_stage is not None

    hs = KILL_CHAIN_STAGES[highest_stage]
    hs_idx = STAGE_ORDER.index(highest_stage)
    urgency    = "IMMEDIATE" if hs_idx >= 4 else "HIGH" if hs_idx >= 2 else "MODERATE"

    response_actions = []
    if hs_idx >= 5:   # C2 or Actions on Objectives
        response_actions += [
            "🔴 CONTAIN: Isolate affected hosts immediately",
            "🔴 BLOCK: Sinkhole or firewall C2 infrastructure",
            "🔴 PRESERVE: Snapshot disk images for forensics before remediation",
            "🔴 NOTIFY: Escalate to IR team and management",
        ]
    if hs_idx >= 3:   # Exploitation onward
        response_actions += [
            "🟠 HUNT: Sweep for lateral movement and additional compromised hosts",
            "🟠 RESET: Force credential rotation on affected accounts",
        ]
    response_actions += [
        f"🟡 MONITOR: Increase logging on Stage {hs['stage_number']+1}: "
        f"{KILL_CHAIN_STAGES[STAGE_ORDER[hs_idx+1]]['name'] if hs_idx < 6 else 'N/A'} "
        f"to detect further progression",
        "🟢 DOCUMENT: Record all IOCs for threat intel enrichment",
    ]

    result = _envelope(
        "track_attack_progression",
        "success",
        {
            "events_analyzed":        len(events),
            "stages_observed":        len(reached_stages),
            "highest_stage_reached": {
                "stage_number": hs["stage_number"],
                "stage":        highest_stage,
                "name":         hs["name"],
                "soc_priority": hs["soc_priority"],
            },
            "urgency":                urgency,
            "response_actions":       response_actions,
            "timeline":               timeline,
            "progression_matrix":     timeline,
            "attacker_has_c2":        stage_activity.get("command_and_control", []) != [],
            "attacker_has_persistence": stage_activity.get("installation", []) != [],
            "attacker_exfiltrating": stage_activity.get("actions_on_objectives", []) != [],
        },
        {"stages_coverage": f"{len(reached_stages)}/{len(STAGE_ORDER)}"},
    )
    logger.info("track_attack_progression: %d events → highest stage: %s", len(events), highest_stage)
    return result


# ─────────────────────────────────────────────
# Resource — killchain://stages
# ─────────────────────────────────────────────
@mcp.resource("killchain://stages")
async def killchain_stages() -> str:
    """
    Complete Cyber Kill Chain framework: all 7 stages with descriptions,
    MITRE ATT&CK mappings, IOC patterns, and defensive controls.
    Returns structured JSON reference.
    """
    framework = {
        "framework": "Lockheed Martin Cyber Kill Chain",
        "version": "2.0",
        "reference": "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html",
        "total_stages": 7,
        "stages": {
            key: {
                "stage_number":       data["stage_number"],
                "name":               data["name"],
                "description":        data["description"],
                "objective":          data["objective"],
                "soc_priority":       data["soc_priority"],
                "mitre_tactics":      data["mitre_tactics"],
                "mitre_tactics_names": data["mitre_tactics_names"],
                "defensive_controls": data["defensive_controls"],
                "detection_opportunities": data["detection_opportunities"],
                "ioc_patterns":       data["ioc_patterns"],
            }
            for key, data in KILL_CHAIN_STAGES.items()
        },
        "mitre_tactic_mapping": MITRE_TACTIC_TO_STAGE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(framework, indent=2)


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting Cyber Kill Chain MCP Server")
    mcp.run(transport="stdio")
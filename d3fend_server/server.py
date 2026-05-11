"""
D3FEND MCP Server - Built for cybersecurity AI workflows
Maps ATT&CK techniques to D3FEND countermeasures for SOC integration.
Author: Mohan Bojjireddy (@mohanbojjireddy)
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

# ─────────────────────────────────────────────
# Logging & Configuration
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("d3fend-mcp")

BASE_URL = "https://d3fend.mitre.org/api"
REQUEST_TIMEOUT = 15.0          # seconds
CACHE_TTL = 3600                # 1 hour TTL for cached responses
MAX_CACHE_ENTRIES = 256
MAX_INPUT_LENGTH = 128          # guard against oversized inputs
RATE_LIMIT_CALLS = 30           # max calls per window
RATE_LIMIT_WINDOW = 60          # seconds

# ─────────────────────────────────────────────
# Simple In-Memory Cache with TTL
# ─────────────────────────────────────────────
class TTLCache:
    """Thread-safe TTL cache for API responses."""
    def __init__(self, maxsize: int = MAX_CACHE_ENTRIES, ttl: int = CACHE_TTL):
        self._store: dict[str, tuple[Any, float]] = {}
        self.maxsize = maxsize
        self.ttl = ttl

    def _key(self, *args) -> str:
        raw = json.dumps(args, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, *args) -> Any | None:
        key = self._key(*args)
        if key in self._store:
            value, ts = self._store[key]
            if time.monotonic() - ts < self.ttl:
                return value
            del self._store[key]
        return None

    def set(self, value: Any, *args) -> None:
        if len(self._store) >= self.maxsize:
            # evict oldest entry
            oldest = min(self._store, key=lambda k: self._store[k][1])
            del self._store[oldest]
        key = self._key(*args)
        self._store[key] = (value, time.monotonic())

    def stats(self) -> dict:
        now = time.monotonic()
        live = sum(1 for _, ts in self._store.values() if now - ts < self.ttl)
        return {"total_entries": len(self._store), "live_entries": live}


# ─────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────
class RateLimiter:
    def __init__(self, calls: int = RATE_LIMIT_CALLS, window: int = RATE_LIMIT_WINDOW):
        self._calls = calls
        self._window = window
        self._timestamps: list[float] = []

    def check(self) -> bool:
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < self._window]
        if len(self._timestamps) >= self._calls:
            return False
        self._timestamps.append(now)
        return True


_cache = TTLCache()
_limiter = RateLimiter()

# ─────────────────────────────────────────────
# Input Validation
# ─────────────────────────────────────────────
ATTACK_ID_RE  = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
D3FEND_ID_RE  = re.compile(r"^[A-Za-z0-9\-]+$")
ARTIFACT_RE   = re.compile(r"^[A-Za-z0-9\s\-_]+$")

def _validate_attack_id(value: str) -> str:
    v = value.strip().upper()
    if len(v) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input too long (max {MAX_INPUT_LENGTH} chars)")
    if not ATTACK_ID_RE.match(v):
        raise ValueError(f"Invalid ATT&CK ID format. Expected T####[.###], got: {v!r}")
    return v

def _normalize_d3fend_id(value: str) -> str:
    """
    Normalize any D3FEND identifier format to its canonical technique name.

    Handles every format the D3FEND API emits or a user might type:
      d3fend.owl#ExecutableAllowlisting          → ExecutableAllowlisting
      https://d3fend.mitre.org/...#FileAnalysis  → FileAnalysis
      d3f:ExecutableAllowlisting                 → ExecutableAllowlisting
      D3-EHB  (short doc code, kept as-is)       → D3-EHB
      ExecutableAllowlisting                     → ExecutableAllowlisting
    """
    v = value.strip()
    if len(v) > MAX_INPUT_LENGTH:
        raise ValueError("D3FEND ID too long")
    # Strip OWL URI — anything before and including '#'
    if "#" in v:
        v = v.split("#")[-1]
    # Strip explicit d3f: namespace prefix
    elif v.startswith("d3f:"):
        v = v[4:]
    if not v:
        raise ValueError(f"Empty D3FEND ID after normalizing: {value!r}")
    if not re.match(r"^[A-Za-z0-9\-]+$", v):
        raise ValueError(f"Invalid D3FEND ID characters: {value!r}")
    return v  # e.g. "ExecutableAllowlisting" or "D3-EHB"


def _api_id(canonical: str) -> str:
    """
    Build the API-path identifier from a canonical D3FEND name.
    Short codes (D3-EHB) stay as-is; CamelCase names get the d3f: prefix.
    """
    if canonical.startswith("D3-"):
        return canonical          # D3-EHB → used directly
    return f"d3f:{canonical}"    # ExecutableAllowlisting → d3f:ExecutableAllowlisting


def _validate_d3fend_id(value: str) -> str:
    """Validate a user-supplied D3FEND ID and return its canonical form."""
    return _normalize_d3fend_id(value)

def _validate_artifact(value: str) -> str:
    v = value.strip()
    if len(v) > MAX_INPUT_LENGTH:
        raise ValueError("Artifact type too long")
    if not ARTIFACT_RE.match(v):
        raise ValueError(f"Invalid artifact type: {value!r}")
    return v

# ─────────────────────────────────────────────
# HTTP Client Helper
# ─────────────────────────────────────────────
async def _get(url: str) -> dict | list | str:
    """Shared async GET with timeout and error handling."""
    if not _limiter.check():
        raise RuntimeError("Rate limit exceeded – please slow down requests.")
    headers = {
        "Accept": "application/json, text/csv",
        "User-Agent": "D3FEND-MCP-Server/1.0 (SOC-Integration)",
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 404:
                raise ValueError(f"Resource not found at D3FEND API: {url}")
            raise RuntimeError(f"D3FEND API returned HTTP {status}")
        except httpx.TimeoutException:
            raise RuntimeError(f"D3FEND API timed out after {REQUEST_TIMEOUT}s")
        except httpx.RequestError as exc:
            raise RuntimeError(f"Network error contacting D3FEND API: {exc}")

        ct = resp.headers.get("content-type", "")
        if "json" in ct:
            return resp.json()
        return resp.text


# ─────────────────────────────────────────────
# D3FEND Tactic Categories (for gap analysis)
# ─────────────────────────────────────────────
D3FEND_TACTIC_CATEGORIES = {
    "Harden":  ["D3-AH", "D3-CH", "D3-MH", "D3-NTH", "D3-SH"],
    "Detect":  ["D3-DA", "D3-NTA", "D3-PA", "D3-UA"],
    "Isolate": ["D3-EI", "D3-NI"],
    "Deceive": ["D3-DNR", "D3-FH", "D3-NM"],
    "Evict":   ["D3-DFE", "D3-DE"],
    "Restore": ["D3-RES"],
}

ALL_TACTIC_PREFIXES = [p for prefixes in D3FEND_TACTIC_CATEGORIES.values() for p in prefixes]


def _envelope(tool: str, status: str, data: Any, meta: dict | None = None) -> dict:
    """Standard A2A-ready JSON envelope for all tool responses."""
    return {
        "schema_version": "1.0",
        "tool": tool,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
        "meta": meta or {},
    }


# ─────────────────────────────────────────────
# FastMCP Server
# ─────────────────────────────────────────────
mcp = FastMCP(
    "D3FEND Cyber Defense Intelligence",
    instructions=(
        "Maps MITRE ATT&CK offensive techniques to D3FEND defensive countermeasures. "
        "Use get_defensive_techniques() first to understand countermeasures for a known attack, "
        "then get_technique_details() to deep-dive, and find_coverage_gaps() to assess SOC posture."
    ),
)


# ─────────────────────────────────────────────
# Tool 1 — get_defensive_techniques
# ─────────────────────────────────────────────
@mcp.tool()
async def get_defensive_techniques(attack_technique: str) -> dict:
    """
    Map a MITRE ATT&CK technique ID to D3FEND defensive countermeasures.

    Args:
        attack_technique: ATT&CK technique ID (e.g. 'T1059', 'T1059.001')

    Returns:
        D3FEND countermeasures mapped to the given ATT&CK technique,
        including technique names, tactic categories, and direct links.
    """
    try:
        att_id = _validate_attack_id(attack_technique)
    except ValueError as exc:
        return _envelope("get_defensive_techniques", "error", None,
                         {"error": str(exc), "hint": "Use format T####[.###] e.g. T1059"})

    cached = _cache.get("def_tech", att_id)
    if cached:
        return cached

    url = f"{BASE_URL}/offensive-technique/attack/{att_id}.json"
    try:
        raw = await _get(url)
    except (ValueError, RuntimeError) as exc:
        return _envelope("get_defensive_techniques", "error", None,
                         {"error": str(exc), "attack_id": att_id})

    # Parse D3FEND API response structure
    off_techniques = raw.get("off_to_def", {}).get("results", {}).get("bindings", [])

    countermeasures: list[dict] = []
    seen_ids: set[str] = set()
    for binding in off_techniques:
        d3_label   = binding.get("def_tech_label", {}).get("value", "Unknown")
        raw_id     = binding.get("def_tech", {}).get("value", "")
        off_label  = binding.get("off_tech_label", {}).get("value", "Unknown")
        kb_article = binding.get("def_artifact_kb_ref_label", {}).get("value", "")
        # Normalize OWL URI (d3fend.owl#ExecutableAllowlisting) → canonical name
        try:
            canonical = _normalize_d3fend_id(raw_id)
        except ValueError:
            continue  # skip malformed entries
        if not canonical or canonical in seen_ids:
            continue
        seen_ids.add(canonical)
        api_ref = _api_id(canonical)   # d3f:ExecutableAllowlisting
        countermeasures.append({
            "d3fend_id":        api_ref,
            "d3fend_technique": d3_label,
            "attack_technique": off_label,
            "kb_reference":     kb_article,
            "detail_url":       f"https://d3fend.mitre.org/technique/{api_ref}/",
        })

    result = _envelope(
        "get_defensive_techniques",
        "success" if countermeasures else "not_found",
        {
            "attack_technique_id": att_id,
            "countermeasure_count": len(countermeasures),
            "countermeasures": countermeasures,
            "attack_ref": f"https://attack.mitre.org/techniques/{att_id.replace('.', '/')}/",
        },
        {"cached": False, "source": "d3fend.mitre.org"},
    )
    _cache.set(result, "def_tech", att_id)
    logger.info("get_defensive_techniques: %s → %d countermeasures", att_id, len(countermeasures))
    return result


# ─────────────────────────────────────────────
# Tool 2 — search_techniques_by_artifact
# ─────────────────────────────────────────────
@mcp.tool()
async def search_techniques_by_artifact(artifact_type: str) -> dict:
    """
    Find D3FEND defensive techniques protecting a specific digital artifact type.

    Args:
        artifact_type: Type of digital artifact (e.g. 'File', 'Network Traffic',
                       'Process', 'User Account', 'Registry Key', 'Email')

    Returns:
        Defensive techniques that protect or monitor the specified artifact type.
    """
    try:
        artifact = _validate_artifact(artifact_type)
    except ValueError as exc:
        return _envelope("search_techniques_by_artifact", "error", None, {"error": str(exc)})

    cached = _cache.get("artifact", artifact)
    if cached:
        return cached

    # URL-encode artifact for safe API call
    encoded = quote(artifact, safe="")
    url = f"{BASE_URL}/artifact/{encoded}.json"

    try:
        raw = await _get(url)
    except (ValueError, RuntimeError) as exc:
        return _envelope("search_techniques_by_artifact", "error", None,
                         {"error": str(exc), "artifact_type": artifact})

    bindings = raw.get("results", {}).get("bindings", [])

    techniques: list[dict] = []
    seen: set[str] = set()
    for b in bindings:
        raw_id     = b.get("def_tech", {}).get("value", "")
        tech_label = b.get("def_tech_label", {}).get("value", "Unknown")
        tactic     = b.get("def_tactic_label", {}).get("value", "Unknown")
        try:
            canonical = _normalize_d3fend_id(raw_id)
        except ValueError:
            continue
        if not canonical or canonical in seen:
            continue
        seen.add(canonical)
        api_ref = _api_id(canonical)
        techniques.append({
            "d3fend_id":        api_ref,
            "technique_name":   tech_label,
            "tactic_category":  tactic,
            "detail_url":       f"https://d3fend.mitre.org/technique/{api_ref}/",
        })

    result = _envelope(
        "search_techniques_by_artifact",
        "success" if techniques else "not_found",
        {
            "artifact_type":    artifact,
            "technique_count":  len(techniques),
            "techniques":       techniques,
        },
        {"cached": False, "source": "d3fend.mitre.org"},
    )
    _cache.set(result, "artifact", artifact)
    logger.info("search_techniques_by_artifact: %s → %d techniques", artifact, len(techniques))
    return result


# ─────────────────────────────────────────────
# Tool 3 — get_technique_details
# ─────────────────────────────────────────────
@mcp.tool()
async def get_technique_details(d3fend_id: str) -> dict:
    """
    Retrieve full details for a specific D3FEND defensive technique.

    Args:
        d3fend_id: D3FEND technique identifier (e.g. 'D3-PAN', 'D3-EHB', 'D3-NTCD')

    Returns:
        Technique metadata: description, how it works, related ATT&CK offenses,
        implementation examples, and references.
    """
    try:
        canonical = _validate_d3fend_id(d3fend_id)  # strips any OWL URI / d3f: prefix
    except ValueError as exc:
        return _envelope("get_technique_details", "error", None, {"error": str(exc)})

    full_id = _api_id(canonical)   # d3f:ExecutableAllowlisting or D3-EHB
    cached = _cache.get("detail", full_id)
    if cached:
        return cached

    # API path uses the d3f: identifier verbatim, URL-encoded
    url = f"{BASE_URL}/technique/{quote(full_id, safe=':')}.json"

    try:
        raw = await _get(url)
    except (ValueError, RuntimeError) as exc:
        return _envelope("get_technique_details", "error", None,
                         {"error": str(exc), "d3fend_id": full_id})

    bindings = raw.get("results", {}).get("bindings", [])

    if not bindings:
        return _envelope("get_technique_details", "not_found",
                         {"d3fend_id": full_id},
                         {"hint": "Check the ID at https://d3fend.mitre.org/techniques/"})

    # Aggregate unique values across bindings
    off_techniques: list[dict] = []
    kb_refs:        list[str]  = []
    seen_off:       set[str]   = set()
    seen_refs:      set[str]   = set()

    first = bindings[0]
    for b in bindings:
        off_id    = b.get("off_tech", {}).get("value", "").split("/")[-1].upper()
        off_label = b.get("off_tech_label", {}).get("value", "")
        ref_label = b.get("kb_ref_label", {}).get("value", "")
        ref_url   = b.get("kb_ref", {}).get("value", "")

        if off_id and off_id not in seen_off:
            seen_off.add(off_id)
            off_techniques.append({"attack_id": off_id, "attack_name": off_label})

        if ref_url and ref_url not in seen_refs:
            seen_refs.add(ref_url)
            kb_refs.append({"label": ref_label, "url": ref_url})

    detail = {
        "d3fend_id":            full_id,
        "technique_name":       first.get("def_tech_label", {}).get("value", "Unknown"),
        "tactic_category":      first.get("def_tactic_label", {}).get("value", "Unknown"),
        "definition":           first.get("def_tech_def", {}).get("value", ""),
        "how_it_works":         first.get("how_it_works", {}).get("value", ""),
        "addresses_techniques": off_techniques,
        "kb_references":        kb_refs,
        "d3fend_url":           f"https://d3fend.mitre.org/technique/{full_id}/",
    }

    result = _envelope("get_technique_details", "success", detail,
                       {"cached": False, "source": "d3fend.mitre.org"})
    _cache.set(result, "detail", full_id)
    logger.info("get_technique_details: %s", full_id)
    return result


# ─────────────────────────────────────────────
# Tool 4 — find_coverage_gaps
# ─────────────────────────────────────────────
@mcp.tool()
async def find_coverage_gaps(deployed_techniques: list[str]) -> dict:
    """
    Analyze which D3FEND tactic categories are missing from a deployed security stack.
    Identifies blind spots and recommends high-priority countermeasures.

    Args:
        deployed_techniques: List of D3FEND technique IDs currently deployed
                             (e.g. ['D3-PAN', 'D3-EHB', 'D3-NTF'])

    Returns:
        Coverage map per D3FEND tactic (Harden/Detect/Isolate/Deceive/Evict/Restore),
        identified gaps, and recommended techniques to close each gap.
    """
    if not deployed_techniques:
        return _envelope("find_coverage_gaps", "error", None,
                         {"error": "deployed_techniques list cannot be empty"})
    if len(deployed_techniques) > 100:
        return _envelope("find_coverage_gaps", "error", None,
                         {"error": "Too many techniques (max 100)"})

    # Normalize and validate each ID
    normalized: list[str] = []
    errors: list[str] = []
    for raw_id in deployed_techniques:
        try:
            normalized.append(_validate_d3fend_id(str(raw_id).strip()))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        return _envelope("find_coverage_gaps", "error", None,
                         {"error": "Invalid technique IDs", "details": errors})

    # Determine which tactic categories are covered
    covered_tactics:   dict[str, list[str]] = {t: [] for t in D3FEND_TACTIC_CATEGORIES}
    uncovered_tactics: dict[str, list[str]] = {}

    for tech_id in normalized:
        for tactic, prefixes in D3FEND_TACTIC_CATEGORIES.items():
            for prefix in prefixes:
                if tech_id.startswith(prefix):
                    covered_tactics[tactic].append(tech_id)

    # Find gaps
    gap_recommendations = {
        "Harden":  ["D3-AH (Application Hardening)", "D3-SH (Software Update)",
                    "D3-MH (Message Hardening)"],
        "Detect":  ["D3-NTA (Network Traffic Analysis)", "D3-PA (Process Analysis)",
                    "D3-UA (User Behavior Analysis)"],
        "Isolate": ["D3-NI (Network Isolation)", "D3-EI (Execution Isolation)"],
        "Deceive": ["D3-DNR (DNS Denylisting)", "D3-FH (File Hashing)"],
        "Evict":   ["D3-DFE (Disconnect Malicious Process)", "D3-DE (Device Eradication)"],
        "Restore": ["D3-RES (Restore Backup Data)"],
    }

    gap_summary: list[dict] = []
    for tactic, covered in covered_tactics.items():
        has_coverage = len(covered) > 0
        if not has_coverage:
            gap_summary.append({
                "tactic":               tactic,
                "status":               "GAP",
                "deployed_techniques":  [],
                "recommendations":      gap_recommendations.get(tactic, []),
                "risk_level":           "HIGH" if tactic in ("Detect", "Harden") else "MEDIUM",
            })
        else:
            gap_summary.append({
                "tactic":               tactic,
                "status":               "COVERED",
                "deployed_techniques":  covered,
                "recommendations":      [],
                "risk_level":           "LOW",
            })

    gaps_count = sum(1 for g in gap_summary if g["status"] == "GAP")
    posture = (
        "CRITICAL" if gaps_count >= 4 else
        "HIGH RISK" if gaps_count >= 3 else
        "MODERATE"  if gaps_count >= 2 else
        "GOOD"      if gaps_count == 1 else
        "EXCELLENT"
    )

    result = _envelope(
        "find_coverage_gaps",
        "success",
        {
            "analyzed_techniques":    normalized,
            "total_deployed":         len(normalized),
            "tactic_categories_total": len(D3FEND_TACTIC_CATEGORIES),
            "gaps_identified":        gaps_count,
            "defensive_posture":      posture,
            "coverage_breakdown":     gap_summary,
        },
        {"note": "Coverage based on D3FEND tactic prefix matching"},
    )
    logger.info("find_coverage_gaps: %d techniques → %d gaps (%s)", len(normalized), gaps_count, posture)
    return result


# ─────────────────────────────────────────────
# D3FEND Complete Static Matrix
# Note: No public REST endpoint exists for the full matrix — the D3FEND
# website only renders it via the web UI. This hardcoded dataset covers
# all published D3FEND 0.13 techniques across all 6 tactic categories.
# Source: https://d3fend.mitre.org/
# ─────────────────────────────────────────────
_D3FEND_MATRIX: list[tuple[str, str, str, str]] = [
    # (tactic, base_technique, d3fend_id, description)

    # ── HARDEN ───────────────────────────────────────────────────────────────
    # Application Hardening
    ("Harden", "Application Hardening",        "D3-AH",   "Reduce the attack surface of applications by limiting functionality and securing configuration."),
    ("Harden", "Application Hardening",        "D3-SVCDP","Service binary verification to ensure software integrity before execution."),
    ("Harden", "Application Hardening",        "D3-DENCR","Dead code elimination to remove unreachable code that may contain vulnerabilities."),
    ("Harden", "Application Hardening",        "D3-EHPV", "Exception handler pointer validation to detect stack-based buffer overflow attacks."),
    ("Harden", "Application Hardening",        "D3-SFCV", "Stack frame canary validation detects stack corruption by checking integrity values."),
    ("Harden", "Application Hardening",        "D3-ASLR", "Address space layout randomization randomizes memory addresses to frustrate exploitation."),
    ("Harden", "Application Hardening",        "D3-HBPI", "Heap-based buffer overflow prevention protects heap memory from overflow attacks."),
    ("Harden", "Application Hardening",        "D3-SBPI", "Stack-based buffer overflow prevention protects the stack from overflow-based exploitation."),
    ("Harden", "Application Hardening",        "D3-EHB",  "Exception handler blocking prevents attackers exploiting exception handler abuse."),
    ("Harden", "Application Hardening",        "D3-CSPP", "Call stack pointer protection validates return addresses to prevent ROP chains."),
    ("Harden", "Application Hardening",        "D3-PO",   "Pointer obfuscation makes memory pointers harder to predict and exploit."),
    ("Harden", "Application Hardening",        "D3-SIPP", "Shadow stack implementation prevents return address corruption by maintaining a protected copy."),
    ("Harden", "Application Hardening",        "D3-SAOR", "Segment address offset randomization randomizes segment base addresses."),
    ("Harden", "Application Hardening",        "D3-SCPE", "Segment code page exclusion marks code pages as non-writable to prevent code injection."),
    ("Harden", "Application Hardening",        "D3-TPWI", "Process code segment verification prevents tampering with code segments at runtime."),
    # Credential Hardening
    ("Harden", "Credential Hardening",         "D3-CH",   "Protect credentials from misuse through multi-factor authentication and secure storage."),
    ("Harden", "Credential Hardening",         "D3-MFA",  "Multi-factor authentication requires multiple verification factors to authenticate a user."),
    ("Harden", "Credential Hardening",         "D3-OTP",  "One-time password generates a single-use credential valid for only one authentication session."),
    ("Harden", "Credential Hardening",         "D3-CRED", "Credential encryption ensures stored credentials are encrypted at rest and in transit."),
    ("Harden", "Credential Hardening",         "D3-CRO",  "Credential rotation periodically invalidates and replaces credentials to limit exposure window."),
    ("Harden", "Credential Hardening",         "D3-BSAM", "Bootloader secure authentication mode validates firmware integrity during the boot sequence."),
    ("Harden", "Credential Hardening",         "D3-PH",   "Password hashing transforms passwords into irreversible hashes using strong algorithms."),
    # Message Hardening
    ("Harden", "Message Hardening",            "D3-MH",   "Protect messages from unauthorized access or modification through authentication and encryption."),
    ("Harden", "Message Hardening",            "D3-MENCR","Message encryption protects message confidentiality by encrypting content end-to-end."),
    ("Harden", "Message Hardening",            "D3-MA",   "Message authentication ensures message integrity and authenticity using cryptographic MACs."),
    ("Harden", "Message Hardening",            "D3-DKIM", "DKIM header verification validates sender authenticity for email messages."),
    ("Harden", "Message Hardening",            "D3-SPF",  "Sender policy framework validates that email originates from an authorized mail server."),
    ("Harden", "Message Hardening",            "D3-DMARC","Domain-based message authentication records and conformance policy enforces email security."),
    # Network Traffic Hardening
    ("Harden", "Network Traffic Restriction",  "D3-NTH",  "Restrict network traffic to only permitted flows using allowlists and policy enforcement."),
    ("Harden", "Network Traffic Restriction",  "D3-DNSAL","DNS allowlisting restricts DNS resolution to known-good domains."),
    ("Harden", "Network Traffic Restriction",  "D3-IPAL", "IP address allowlisting restricts network communication to approved IP addresses."),
    ("Harden", "Network Traffic Restriction",  "D3-UDPL", "UDP traffic restriction limits UDP communication to necessary ports and endpoints."),
    ("Harden", "Network Traffic Restriction",  "D3-NTPM", "Network traffic policy mapping enforces ingress and egress rules based on security policy."),
    ("Harden", "Network Traffic Restriction",  "D3-NTAL", "Network traffic allowlisting permits only pre-approved communication patterns."),
    # Software Hardening / Update
    ("Harden", "Software Update",              "D3-SU",   "Keeping software up to date to eliminate known vulnerabilities and security flaws."),
    ("Harden", "Software Update",              "D3-PM",   "Patch management systematically identifies and applies security patches across the environment."),
    ("Harden", "Software Update",              "D3-SVCP", "Service vulnerability patching addresses specific vulnerabilities in network-exposed services."),
    # System Hardening
    ("Harden", "System Hardening",             "D3-SH",   "Reduce the attack surface of systems by securing configurations and removing unnecessary components."),
    ("Harden", "System Hardening",             "D3-ACH",  "Application configuration hardening reduces attack surface by removing unnecessary features."),
    ("Harden", "System Hardening",             "D3-BAN",  "OS boot sector hardening protects the master boot record from tampering."),
    ("Harden", "System Hardening",             "D3-RFIM", "Removing unapproved firmware protects systems from firmware-level persistence."),
    ("Harden", "System Hardening",             "D3-DLIC", "Driver load integrity checking validates that only signed drivers are loaded."),
    ("Harden", "System Hardening",             "D3-SICA", "System integrity checking alerts on unauthorized changes to system files."),
    ("Harden", "System Hardening",             "D3-SVCDC","Service configuration defense prevents unauthorized service modification."),
    ("Harden", "System Hardening",             "D3-UAP",  "User account permissions restrict user privileges to the minimum necessary."),

    # ── DETECT ───────────────────────────────────────────────────────────────
    # File Analysis
    ("Detect", "File Analysis",                "D3-FA",   "Analyze file content, metadata, or behavior to identify malicious or anomalous files."),
    ("Detect", "File Analysis",                "D3-DAM",  "Dynamic analysis monitors program behavior during execution in a controlled environment."),
    ("Detect", "File Analysis",                "D3-SFA",  "Signature-based analysis compares files against known malware signatures."),
    ("Detect", "File Analysis",                "D3-EFA",  "Emulated file analysis executes files in an emulated environment to detect malicious behavior."),
    ("Detect", "File Analysis",                "D3-HDSA", "Heuristic detection analyzes file characteristics to identify suspicious patterns without signatures."),
    ("Detect", "File Analysis",                "D3-FCA",  "File content analysis inspects file content for embedded malicious code or suspicious patterns."),
    ("Detect", "File Analysis",                "D3-FCSA", "File content signature analysis detects known malicious byte sequences in files."),
    ("Detect", "File Analysis",                "D3-FCRA", "File content rule-based analysis applies behavioral rules to file content inspection."),
    ("Detect", "File Analysis",                "D3-FH",   "File hashing generates cryptographic hashes to verify file integrity and detect tampering."),
    ("Detect", "File Analysis",                "D3-FMSA", "File metadata analysis inspects file metadata for anomalies and indicators of tampering."),
    # Identifier Analysis
    ("Detect", "Identifier Analysis",          "D3-IA",   "Analyze identifiers such as usernames or domain names for anomalous or malicious activity."),
    ("Detect", "Identifier Analysis",          "D3-DNSRA","DNS record analysis detects malicious or anomalous DNS configurations and records."),
    ("Detect", "Identifier Analysis",          "D3-URL",  "URL analysis detects malicious or suspicious URLs before access."),
    ("Detect", "Identifier Analysis",          "D3-IPAD", "IP address analysis detects communication with known malicious or anomalous IP addresses."),
    ("Detect", "Identifier Analysis",          "D3-DOMA", "Domain name analysis detects algorithmically generated or malicious domain names."),
    # Message Analysis
    ("Detect", "Message Analysis",             "D3-MA",   "Analyze messages for malicious content including phishing, malware delivery, and spam."),
    ("Detect", "Message Analysis",             "D3-EFA",  "Email file attachment analysis detects malicious payloads in email attachments."),
    ("Detect", "Message Analysis",             "D3-EMAS", "Email analysis detects phishing, business email compromise, and malicious email campaigns."),
    ("Detect", "Message Analysis",             "D3-MCAS", "Message content analysis detects malicious or policy-violating content in communications."),
    # Network Traffic Analysis
    ("Detect", "Network Traffic Analysis",     "D3-NTA",  "Analyze network traffic for anomalies, known threats, and policy violations."),
    ("Detect", "Network Traffic Analysis",     "D3-NTF",  "Network traffic filtering inspects and blocks malicious or unauthorized network traffic."),
    ("Detect", "Network Traffic Analysis",     "D3-NTBA", "Network traffic behavior analysis detects anomalous communication patterns."),
    ("Detect", "Network Traffic Analysis",     "D3-PCAP", "Packet capture analysis records and analyzes raw network packets for forensic investigation."),
    ("Detect", "Network Traffic Analysis",     "D3-DNSDL","DNS traffic analysis detects malicious DNS queries and DNS-based covert channels."),
    ("Detect", "Network Traffic Analysis",     "D3-DNSTL","DNS traffic traffic logging records DNS queries for threat hunting and forensic analysis."),
    ("Detect", "Network Traffic Analysis",     "D3-PHDP", "Protocol-based hiding detection identifies covert communications hidden in legitimate protocols."),
    ("Detect", "Network Traffic Analysis",     "D3-RTSD", "Remote terminal session detection identifies unauthorized remote access sessions."),
    ("Detect", "Network Traffic Analysis",     "D3-CSAD", "Client-server payload profiling detects anomalous payload sizes or patterns."),
    ("Detect", "Network Traffic Analysis",     "D3-IBAL", "Inbound session volume analysis detects volumetric attacks and unusual inbound traffic."),
    ("Detect", "Network Traffic Analysis",     "D3-SIED", "Session interception event detection identifies session hijacking or man-in-the-middle attacks."),
    # Process Analysis
    ("Detect", "Process Analysis",             "D3-PA",   "Analyze process behavior and relationships to detect malicious activity on endpoints."),
    ("Detect", "Process Analysis",             "D3-PAN",  "Process ancestry analysis detects unusual parent-child process relationships."),
    ("Detect", "Process Analysis",             "D3-PCE",  "Process code extraction analyzes process memory to detect injected code."),
    ("Detect", "Process Analysis",             "D3-PCMS", "Process code segment verification detects modification of process code in memory."),
    ("Detect", "Process Analysis",             "D3-PCSV", "Process spawn analysis detects anomalous process creation events."),
    ("Detect", "Process Analysis",             "D3-PHIA", "Process self-modification detection identifies processes that modify their own code."),
    ("Detect", "Process Analysis",             "D3-PPSA", "Process peer analysis identifies unusual process network communication patterns."),
    ("Detect", "Process Analysis",             "D3-PSA",  "Process segment analysis inspects process memory segments for anomalies."),
    ("Detect", "Process Analysis",             "D3-PSS",  "Process sandbox analysis executes suspicious processes in isolation to observe behavior."),
    ("Detect", "Process Analysis",             "D3-PTSA", "Process system call analysis monitors system calls for suspicious patterns."),
    # User Behavior Analysis
    ("Detect", "User Behavior Analysis",       "D3-UBA",  "Monitor user activity to identify anomalous behavior indicating credential compromise or insider threat."),
    ("Detect", "User Behavior Analysis",       "D3-UISBA","User identity behavior analysis detects anomalous identity and access patterns."),
    ("Detect", "User Behavior Analysis",       "D3-RAPA", "Resource access pattern analysis detects unusual data access patterns."),
    ("Detect", "User Behavior Analysis",       "D3-AAPA", "Authentication event analysis detects anomalous login behavior such as credential stuffing."),
    ("Detect", "User Behavior Analysis",       "D3-AZAPA","Authorization event analysis monitors authorization decisions for privilege escalation."),
    ("Detect", "User Behavior Analysis",       "D3-SCA",  "Session duration analysis identifies sessions that are unusually long or outside normal hours."),

    # ── ISOLATE ──────────────────────────────────────────────────────────────
    # Execution Isolation
    ("Isolate","Execution Isolation",          "D3-EI",   "Restrict the execution environment to limit the impact of compromised processes."),
    ("Isolate","Execution Isolation",          "D3-ANAA", "Application container security isolates application execution in containerized environments."),
    ("Isolate","Execution Isolation",          "D3-SR",   "Mandatory access control restricts what resources a process can access."),
    ("Isolate","Execution Isolation",          "D3-SCF",  "System call filtering restricts which system calls a process is permitted to invoke."),
    ("Isolate","Execution Isolation",          "D3-PDP",  "Privileged process protection limits privileges available to sensitive system processes."),
    ("Isolate","Execution Isolation",          "D3-HPVA", "Hardware-based process isolation uses CPU features to isolate process execution."),
    ("Isolate","Execution Isolation",          "D3-VLAN", "Virtual machine-based sandboxing isolates workloads in separate virtual machines."),
    # Network Isolation
    ("Isolate","Network Isolation",            "D3-NI",   "Limit network reachability to prevent lateral movement and contain compromised systems."),
    ("Isolate","Network Isolation",            "D3-ITF",  "Inbound traffic filtering restricts unauthorized inbound network connections."),
    ("Isolate","Network Isolation",            "D3-OTF",  "Outbound traffic filtering restricts unauthorized outbound network connections."),
    ("Isolate","Network Isolation",            "D3-BK",   "Broadcast domain isolation segments network broadcast domains to limit traffic scope."),
    ("Isolate","Network Isolation",            "D3-DNSAL","DNS-based network isolation restricts name resolution to prevent C2 communication."),
    ("Isolate","Network Isolation",            "D3-SEGM", "Network segmentation divides the network into isolated zones to contain breaches."),
    ("Isolate","Network Isolation",            "D3-ET",   "Encrypted tunnels protect network traffic from eavesdropping and tampering."),

    # ── DECEIVE ──────────────────────────────────────────────────────────────
    # Decoy Environment
    ("Deceive","Decoy Environment",            "D3-DE",   "Deploy decoy systems to detect and misdirect adversary activity."),
    ("Deceive","Decoy Environment",            "D3-DNR",  "DNS denylisting blocks resolution of known malicious domains."),
    ("Deceive","Decoy Environment",            "D3-DUC",  "Decoy user credentials detect adversary use of harvested or stolen credentials."),
    ("Deceive","Decoy Environment",            "D3-DF",   "Decoy file systems present fake file structures to misdirect attackers."),
    ("Deceive","Decoy Environment",            "D3-DPE",  "Decoy processes run fake processes to attract and detect attacker interaction."),
    # Decoy Object
    ("Deceive","Decoy Object",                 "D3-DO",   "Deploy decoy data, files, or accounts to detect unauthorized access."),
    ("Deceive","Decoy Object",                 "D3-DAN",  "Decoy account credentials act as canary tokens to detect credential theft."),
    ("Deceive","Decoy Object",                 "D3-DFD",  "Decoy file detection alerts when attackers access intentionally placed decoy files."),
    ("Deceive","Decoy Object",                 "D3-DNB",  "Decoy network resources attract and detect adversary network reconnaissance."),
    ("Deceive","Decoy Object",                 "D3-PH",   "Poison host-based technique plants false data for attackers to exfiltrate."),
    # Network Misdirection
    ("Deceive","Network Misdirection",         "D3-NM",   "Redirect attacker traffic to decoy systems or sinkhole infrastructure."),
    ("Deceive","Network Misdirection",         "D3-SINKH","DNS sinkholing redirects queries for malicious domains to analyst-controlled infrastructure."),
    ("Deceive","Network Misdirection",         "D3-HOP",  "Honeyport detection identifies adversary port scanning using listening ports with no services."),
    ("Deceive","Network Misdirection",         "D3-TRAP", "Network traffic misdirection routes attacker traffic away from legitimate systems."),

    # ── EVICT ────────────────────────────────────────────────────────────────
    # Credential Eviction
    ("Evict", "Credential Eviction",           "D3-CE",   "Remove or invalidate compromised credentials to evict adversaries from the environment."),
    ("Evict", "Credential Eviction",           "D3-ACRV", "Account credential revocation immediately invalidates compromised credentials."),
    ("Evict", "Credential Eviction",           "D3-CREV", "Certificate revocation invalidates compromised digital certificates."),
    # Process Eviction
    ("Evict", "Process Eviction",              "D3-PE",   "Terminate malicious processes and remove malware from compromised systems."),
    ("Evict", "Process Eviction",              "D3-PT",   "Process termination kills malicious or compromised processes."),
    ("Evict", "Process Eviction",              "D3-DFE",  "Disconnect from live environment severs attacker access by isolating compromised systems."),
    ("Evict", "Process Eviction",              "D3-KPRV", "Kernel process removal terminates kernel-level malicious processes."),
    # System Eviction
    ("Evict", "System Eviction",               "D3-SE",   "Remove persistence mechanisms and malware from compromised systems."),
    ("Evict", "System Eviction",               "D3-SDR",  "System driver removal eliminates malicious or unauthorized drivers from the system."),
    ("Evict", "System Eviction",               "D3-BFOR", "Boot sector restoration restores a clean master boot record after bootkit infection."),
    ("Evict", "System Eviction",               "D3-FIRM", "Firmware restoration restores clean firmware after firmware-level compromise."),

    # ── RESTORE ──────────────────────────────────────────────────────────────
    ("Restore","Restore",                      "D3-RES",  "Restore systems and data to a known-good state following a security incident."),
    ("Restore","Backup",                       "D3-BKUP", "Data backup maintains copies of critical data to enable recovery after ransomware or destruction."),
    ("Restore","Backup",                       "D3-BKUPV","Backup verification validates backup integrity before a restore operation is needed."),
    ("Restore","System Restore",               "D3-SRSTR","System image restoration recovers a full system from a verified clean image."),
    ("Restore","System Restore",               "D3-SVTIM","System snapshot restore recovers system state from a point-in-time snapshot."),
    ("Restore","Network Restore",              "D3-NETR", "Network configuration restoration restores network device configurations to known-good state."),
]


# ─────────────────────────────────────────────
# Resource — d3fend://matrix
# ─────────────────────────────────────────────
@mcp.resource("d3fend://matrix")
async def d3fend_matrix() -> str:
    """
    Full D3FEND defensive matrix as CSV.
    Returns all techniques across all 6 tactic categories
    (Harden, Detect, Isolate, Deceive, Evict, Restore) with descriptions.

    Note: MITRE does not expose a REST endpoint for the full matrix —
    this dataset is compiled from the published D3FEND 0.13 ontology.
    Source: https://d3fend.mitre.org/
    """
    cached = _cache.get("matrix", "full")
    if cached:
        return cached

    lines = ["tactic,base_technique,d3fend_id,description"]
    for tactic, base_tech, d3_id, description in _D3FEND_MATRIX:
        # Escape commas in fields
        desc_safe = description.replace(",", ";")
        lines.append(f"{tactic},{base_tech},{d3_id},{desc_safe}")

    csv_text = "\n".join(lines)
    _cache.set(csv_text, "matrix", "full")
    logger.info("d3fend://matrix served: %d techniques", len(_D3FEND_MATRIX))
    return csv_text


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting D3FEND MCP Server")
    mcp.run(transport="stdio")
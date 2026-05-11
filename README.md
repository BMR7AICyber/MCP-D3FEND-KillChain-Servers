# Cyber Defense MCP Suite - Built for cybersecurity AI workflows
## D3FEND + Cyber Kill Chain — Production MCP Servers for SOC Integration

Two FastMCP servers that bring MITRE D3FEND countermeasure intelligence and
Lockheed Martin Kill Chain analysis directly into Claude Desktop for SOC workflows.

---

## Architecture Overview

```
Claude Desktop
     │
     ├─── MCP Protocol (stdio) ───► d3fend_server/server.py
     │                                    │
     │                                    └──► D3FEND API (d3fend.mitre.org/api)
     │                                         [with TTL cache + rate limiter]
     │
     └─── MCP Protocol (stdio) ───► killchain_server/server.py
                                         │
                                         └──► Static Kill Chain KB + MITRE mapping
                                              [no external calls — fully offline]
```

**D3FEND Server** — Calls the live `d3fend.mitre.org` REST API with caching  
**Kill Chain Server** — Runs fully offline from an embedded knowledge base

---

## Project Structure

```
mcp-cyber-servers/
├── d3fend_server/
│   ├── server.py          # D3FEND MCP server (4 tools + 1 resource)
│   └── requirements.txt
├── killchain_server/
│   ├── server.py          # Kill Chain MCP server (4 tools + 1 resource)
│   └── requirements.txt
├── docs/
│   └── example_queries.md # 16 ready-to-use Claude prompts
├── claude_desktop_config.json
└── README.md
```

---

## Quick Setup

### Prerequisites
- Python 3.11+
- Claude Desktop (latest version)

### Step 1 — Clone / Download

```bash
# Place the mcp-cyber-servers folder somewhere stable, e.g.:
# macOS / Linux:  ~/tools/mcp-cyber-servers
# Windows:        C:\tools\mcp-cyber-servers
```

### Step 2 — Install Dependencies

```bash
# D3FEND server (needs httpx for API calls)
cd mcp-cyber-servers/d3fend_server
pip install -r requirements.txt

# Kill Chain server (MCP only — no external dependencies)
cd ../killchain_server
pip install -r requirements.txt
```

### Step 3 — Configure Claude Desktop

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Copy the config below and **update the paths** to match your system:

```json
{
  "mcpServers": {
    "d3fend-intelligence": {
      "command": "python",
      "args": ["/YOUR/PATH/mcp-cyber-servers/d3fend_server/server.py"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    },
    "killchain-intelligence": {
      "command": "python",
      "args": ["/YOUR/PATH/mcp-cyber-servers/killchain_server/server.py"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

**Windows path example:**
```json
"args": ["C:\\tools\\mcp-cyber-servers\\d3fend_server\\server.py"]
```

### Step 4 — Restart Claude Desktop

After saving the config, fully quit and reopen Claude Desktop.
You should see both servers listed in the tools menu (hammer icon).

---

## Tool Reference

### D3FEND Server

| Tool | Input | Use Case |
|------|-------|----------|
| `get_defensive_techniques` | `attack_technique: str` (e.g. "T1059") | Map ATT&CK ID → D3FEND countermeasures |
| `search_techniques_by_artifact` | `artifact_type: str` (e.g. "Network Traffic") | Find defenses by artifact type |
| `get_technique_details` | `d3fend_id: str` (e.g. "D3-PAN") | Full technique info + KB references |
| `find_coverage_gaps` | `deployed_techniques: List[str]` | Gap analysis across 6 D3FEND tactics |

**Resource:** `d3fend://matrix` — Full defensive matrix as CSV

### Kill Chain Server

| Tool | Input | Use Case |
|------|-------|----------|
| `analyze_attack_stage` | `observed_indicators: List[str]` | IOC → Kill chain stage mapping |
| `get_defensive_controls` | `stage: str` | Full playbook for a given stage |
| `map_mitre_to_killchain` | `attack_tactic: str` | ATT&CK tactic → Kill chain stage |
| `track_attack_progression` | `events: List[dict]` | Multi-event attack timeline analysis |

**Resource:** `killchain://stages` — Full framework JSON reference

---

## Security Design

### Input Validation
All tool inputs are validated before processing:
- ATT&CK IDs validated against `T####[.###]` regex
- D3FEND IDs validated against `D3-[A-Za-z0-9-]+` pattern
- Maximum input lengths enforced on all string fields
- Event counts capped at 200 items

### Rate Limiting
D3FEND server enforces **30 requests/minute** against the public API to be a
responsible API consumer and avoid being blocked.

### Caching
Responses cached for **1 hour** with a 256-entry LRU+TTL cache:
- Reduces API calls on repeated queries
- Returns stale-safe responses during API outages (matrix fallback)
- Cache keys are SHA-256 hashed to avoid key injection

### A2A-Ready JSON Envelope
Every tool response follows this standard envelope:
```json
{
  "schema_version": "1.0",
  "tool": "get_defensive_techniques",
  "status": "success | error | not_found | no_match",
  "timestamp": "2024-01-20T14:32:00Z",
  "data": { ... },
  "meta": { ... }
}
```
This makes responses parseable by other agents, SOAR platforms, and automation pipelines.

### What This Does NOT Do
- Does not accept executable code or command strings
- Does not write to disk
- Does not store or log user query content
- Kill Chain server makes zero network calls (fully air-gap safe)

---

## SOC Integration Patterns

### SOAR Playbook Integration
Both servers return structured JSON suitable for SOAR platform ingestion.
Status field enables conditional branching: `success` → enrich ticket,
`error` → human review queue.

### Incident Response Workflow
```
1. Paste IOCs into Claude → analyze_attack_stage()  [Kill Chain]
2. Get stage playbook    → get_defensive_controls()  [Kill Chain]
3. Map to ATT&CK         → get_defensive_techniques() [D3FEND]
4. Assess current posture → find_coverage_gaps()      [D3FEND]
5. Brief leadership      → track_attack_progression() [Kill Chain]
```

### Threat Hunt Workflow
```
1. Hypothesis: Attacker at stage 5 (Installation)
2. get_defensive_controls("installation")     → what to look for
3. search_techniques_by_artifact("Process")  → what defenses should be firing
4. find_coverage_gaps(current_stack)         → identify blind spots
```

---

## Troubleshooting

**Server not appearing in Claude Desktop tools:**
- Check the config JSON is valid (no trailing commas)
- Verify the Python path is absolute, not relative
- Run `python d3fend_server/server.py` directly to check for import errors
- Check Claude Desktop logs: `~/Library/Logs/Claude/` (macOS)

**D3FEND API returning errors:**
- The public D3FEND API occasionally has maintenance windows
- Matrix resource has a static fallback for outages
- Rate limit: if you see "Rate limit exceeded", wait 60 seconds

**"Module not found" errors:**
- Ensure `pip install -r requirements.txt` ran in the correct virtualenv
- Try `python -m pip install mcp httpx` explicitly
- Use `python3` instead of `python` on some systems

---

## References

- MITRE D3FEND: https://d3fend.mitre.org/
- D3FEND API: https://d3fend.mitre.org/api/
- MITRE ATT&CK: https://attack.mitre.org/
- Cyber Kill Chain: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- MCP Specification: https://modelcontextprotocol.io/
- FastMCP Docs: https://github.com/jlowin/fastmcp

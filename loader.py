"""
Stage 1 - Load and validate a scenario file.            (Owner: Role 1)

REFERENCE VERSION written so the pipeline runs end to end. It reads the
intermediate JSON format Role 1 defined in scenarios.json (the output of the
Phase 3 adapter + enrichment step):

    {
      "scenario": "...", "description": "...", "expected_level": "HIGH",
      "resources": [ { "id": "orders_db", "name": "Order records" }, ... ],
      "agents": [
        { "name": "support_agent", "description": "...",
          "tools": [ { "name": "...", "description": "...", "inputSchema": {...}, "scopes": [...],
                       "blast_radius": { "access": "read", "reaches": "orders_db",
                                         "data_trust": "verified",
                                         "requires_human_approval": false,
                                         "sensitivity": 3, "irreversibility": 1 } } ] }
      ]
    }

load_scenario(path) returns a normalised dict that the next stages use:

    "scenario", "description", "expected_level" (or None)
    "resources" : list of {"id", "name", "untrusted": bool}
    "agents"    : list of {"name", "description", "tools"}
    each tool   : {"name", "description", "access", "reaches", "sensitivity",
                   "irreversibility", "data_trust", "requires_human_approval"}

A resource is "untrusted" (an attacker entry point) when any read tool marks it
data_trust "untrusted". Raises ScenarioError with a readable message when the
file is invalid.
"""

import json

VALID_ACCESS = {"read", "write", "delete", "execute"}
VALID_TRUST = {"untrusted", "unverified", "verified", None}
BLAST_FIELDS = ("access", "reaches", "sensitivity", "irreversibility")


class ScenarioError(ValueError):
    """The scenario file is missing a field or refers to something unknown."""


def load_scenario(path):
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise ScenarioError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise ScenarioError(f"{path} is not valid JSON (line {e.lineno}): {e.msg}")
    return normalise(raw)


def normalise(raw):
    for key in ("resources", "agents"):
        if not isinstance(raw.get(key), list) or not raw[key]:
            raise ScenarioError(f"Missing or empty top-level field '{key}'")

    resources, ids = [], set()
    for r in raw["resources"]:
        rid = r.get("id")
        if not rid:
            raise ScenarioError(f"A resource has no 'id': {r}")
        if rid in ids:
            raise ScenarioError(f"Duplicate resource id '{rid}'")
        ids.add(rid)
        resources.append({"id": rid, "name": r.get("name", rid), "untrusted": False})

    agents, agent_names = [], set()
    for a in raw["agents"]:
        name = a.get("name")
        if not name:
            raise ScenarioError(f"An agent has no 'name': {a}")
        if name in agent_names or name in ids:
            raise ScenarioError(f"Name '{name}' is used twice (agent names and resource ids must be unique)")
        agent_names.add(name)
        if not isinstance(a.get("tools"), list):
            raise ScenarioError(f"Agent '{name}' is missing the list field 'tools'")
        agents.append({"name": name, "description": a.get("description", ""),
                       "tools": [_tool(name, t, ids) for t in a["tools"]]})

    by_id = {r["id"]: r for r in resources}
    for a in agents:
        for t in a["tools"]:
            if t["access"] == "read" and t["data_trust"] == "untrusted":
                by_id[t["reaches"]]["untrusted"] = True

    if not any(r["untrusted"] for r in resources):
        raise ScenarioError('No read tool has data_trust "untrusted", so there is no attacker entry point')

    return {
        "scenario": raw.get("scenario", "Unnamed scenario"),
        "description": raw.get("description", ""),
        "expected_level": raw.get("expected_level"),
        "resources": resources,
        "agents": agents,
    }


def _tool(agent, t, ids):
    tname = t.get("name", "?")
    br = t.get("blast_radius")
    if not isinstance(br, dict):
        raise ScenarioError(f"Tool {tname} of agent '{agent}' has no 'blast_radius' object")
    for field in BLAST_FIELDS:
        if field not in br:
            raise ScenarioError(f"Tool {tname} of agent '{agent}' is missing blast_radius '{field}'")
    if br["access"] not in VALID_ACCESS:
        raise ScenarioError(f"Tool {tname}: access '{br['access']}' must be one of {sorted(VALID_ACCESS)}")
    if br["reaches"] not in ids:
        raise ScenarioError(f"Tool {tname} of agent '{agent}' reaches unknown resource '{br['reaches']}'")
    for field in ("sensitivity", "irreversibility"):
        if not isinstance(br[field], int) or not 1 <= br[field] <= 5:
            raise ScenarioError(f"Tool {tname}: '{field}' must be a whole number from 1 to 5")
    trust = br.get("data_trust")
    if trust not in VALID_TRUST:
        raise ScenarioError(f"Tool {tname}: data_trust '{trust}' must be untrusted, unverified, verified or null")
    return {
        "name": tname,
        "description": t.get("description", ""),
        "access": br["access"],
        "reaches": br["reaches"],
        "sensitivity": br["sensitivity"],
        "irreversibility": br["irreversibility"],
        "data_trust": trust,
        "requires_human_approval": bool(br.get("requires_human_approval", False)),
    }

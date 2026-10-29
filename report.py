"""
Stage 4 - Turn scored paths into the ranked report.     (Owner: Role 4)

Works on the scored-path dicts from pathfinder.py. Only "path", "score" and
"reason" are required, so the report also renders hand-made fake paths
(see TestReport in tests/test_scanner.py) before the real pathfinder is plugged in.

Output is plain ASCII so it prints correctly in the Windows console.
"""

WIDTH = 78
LEVELS = [(25, "HIGH"), (10, "MEDIUM"), (0, "LOW")]

IRREVERSIBILITY_WORDS = {
    1: "no lasting change",
    2: "easy to undo",
    3: "undo takes real effort",
    4: "hard to undo",
    5: "cannot be undone",
}


def risk_level(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "LOW"


# ---------------------------------------------------------------- path parts

def _hops(p):
    """Split a path into (agent, tool_name, resource) hops."""
    nodes = p["path"]
    hops = []
    for i in range(1, len(nodes) - 2, 3):
        agent, tool, resource = nodes[i], nodes[i + 1], nodes[i + 2]
        tool_name = tool.split("::", 1)[-1]
        hops.append((agent, tool_name, resource))
    return hops


def _accesses(p, g):
    if g is None:
        return [p.get("access", "?")] * len(_hops(p))
    return [g.nodes[n]["access"] for n in p["path"] if g.has_node(n) and g.nodes[n].get("kind") == "tool"]


def bridges(p, g):
    """Trust edges on the path that start at a shared (not attacker-facing) resource.

    These are the cross-agent links that no single agent's permission list shows.
    """
    found = []
    for agent, _, resource in _hops(p)[:-1]:
        nxt = p["path"][p["path"].index(resource) + 1]
        untrusted = g.nodes[resource].get("untrusted") if g is not None else False
        if not untrusted:
            found.append((resource, nxt))
    return found


def format_path(p, g=None, indent=12):
    """Multi-line drawing of one attack path, one hop per line."""
    pad = " " * indent
    nodes = p["path"]
    if len(nodes) < 4:
        return " -> ".join(nodes)
    lines = [f"[entry] {nodes[0]}"]
    for (agent, tool, resource), access in zip(_hops(p), _accesses(p, g)):
        lines.append(f"{pad}  => steers {agent}")
        lines.append(f"{pad}  -- {tool} ({access}) --> {resource}")
    return "\n".join(lines)


def short_path(p):
    nodes = p["path"]
    if len(nodes) < 4:
        return " -> ".join(nodes)
    agents = [a for a, _, _ in _hops(p)]
    return f"{nodes[0]} -> {' -> '.join(agents)} -> {_hops(p)[-1][1]}"


# ---------------------------------------------------------------- reason / fix

def explain(p, g=None):
    """Plain-language reason for why this path ranks where it does."""
    if "sensitivity" not in p or len(p["path"]) < 4:
        return p.get("reason", "")

    hops = _hops(p)
    accesses = _accesses(p, g)
    entry = p["entry"]
    first_agent = hops[0][0]
    parts = [f"An attacker who can write to {entry} (untrusted input) can inject "
             f"instructions into {first_agent}, which trusts that input."]

    for i in range(len(hops) - 1):
        agent, tool, resource = hops[i]
        next_agent = hops[i + 1][0]
        parts.append(f"{agent} uses {tool} to {accesses[i]} {resource}. "
                     f"{next_agent} trusts {resource}, so the attacker now steers "
                     f"{next_agent} too - without ever touching it directly.")

    last_agent, tool, target = hops[-1]
    rev = p["irreversibility"]
    if p["access"] == "read":
        effect = f"{last_agent} can read {target} with {tool} (sensitivity {p['sensitivity']}/5), a data-exposure risk"
    else:
        effect = (f"{tool} can {p['access']} {target} - sensitivity {p['sensitivity']}/5, "
                  f"irreversibility {rev}/5 ({IRREVERSIBILITY_WORDS.get(rev, '')})")
    parts.append(f"Final action: {effect}.")
    if p.get("requires_human_approval"):
        parts.append("This action is already gated by human approval, so the attacker also "
                     "needs a person to approve it.")

    agents_word = "agent" if p["breadth"] == 1 else "agents"
    parts.append(f"Steering {p['breadth']} {agents_word} gives "
                 f"{p['sensitivity']} x {rev} x {p['breadth']} = {p['score']}.")
    return " ".join(parts)


def suggest_fix(p, g=None):
    """Most effective single change that would remove or shrink this path."""
    if "sensitivity" not in p or len(p["path"]) < 4:
        return "Review this path manually."

    tool, target = p["tool"], p["target"]
    approval = (p["irreversibility"] >= 4 and p["access"] != "read"
                and not p.get("requires_human_approval"))

    links = bridges(p, g)
    if links:
        resource, agent = links[0]
        via = g.edges[resource, agent].get("via", "its read tool") if g is not None else "its read tool"
        fix = (f"Break the cross-agent bridge: {agent} should accept only verified (signed / "
               f"human-approved) content from {resource}, not act on anything posted there. "
               f"Set data_trust of {via} to \"verified\".")
        if approval:
            fix += f" Also require human approval before {tool}."
        return fix
    if approval:
        return (f"Require human approval before {tool} (set requires_human_approval to true), "
                f"because its effect on {target} cannot easily be undone.")
    if p.get("requires_human_approval"):
        return (f"Already gated by human approval. Make sure reviewers can see where the request "
                f"came from, since a steered agent can still ask for {tool}.")
    if p["access"] != "read" and p["sensitivity"] >= 3:
        return (f"Narrow {tool} (least privilege): limit what it can change in {target}, "
                f"or add a confirmation step.")
    if p["access"] == "read" and p["sensitivity"] >= 3:
        return f"Limit {tool} to the fields this agent actually needs from {target}."
    return "Low impact - no change needed. Keep it on the watch list."


# ---------------------------------------------------------------- full report

def _rule(char="-"):
    return char * WIDTH


def build_report(data, paths, worst=None, g=None, what_if=None, top=None, source=None):
    """Return the full ranked report as one string.

    data     loaded scenario dict (for the header)
    paths    scored paths, any order (they are re-ranked here)
    worst    path from the best-first search, cross-checked against the DFS ranking
    what_if  optional list of simulated fixes from scanner.simulate_fixes()
    """
    ranked = sorted(paths, key=lambda p: -p["score"])
    out = [_rule("="), " AI AGENT BLAST-RADIUS REPORT",
           f" Scenario : {data.get('scenario', '?')}"]
    if source:
        out.append(f" File     : {source}")
    out.append(_rule("="))

    if data.get("description"):
        out.append(_wrap(data["description"], 1))
    entries = [r["id"] for r in data.get("resources", []) if r.get("untrusted")]
    cross = sum(1 for p in ranked if p.get("breadth", 1) > 1)
    out.append(f" Agents: {len(data.get('agents', []))}   Resources: {len(data.get('resources', []))}"
               f"   Untrusted entry points: {', '.join(entries) or 'none'}")
    out.append(f" Attack paths found: {len(ranked)}   Cross-agent paths: {cross}")
    out.append("")

    if not ranked:
        out.append(" WORST-CASE BLAST RADIUS: 0  [NONE] - no attack path from any untrusted input.")
        out.append(_rule("="))
        return "\n".join(out)

    top_path = worst or ranked[0]
    out.append(f" WORST-CASE BLAST RADIUS: {top_path['score']}  [{risk_level(top_path['score'])}]")
    out.append(f"   {short_path(top_path)}")
    if worst is not None:
        agree = "matches" if worst["score"] == ranked[0]["score"] else "DOES NOT MATCH"
        out.append(f"   (best-first search result {agree} the DFS maximum of {ranked[0]['score']})")
    out.append("")

    out += [_rule(), " RANKED ATTACK PATHS   score = sensitivity x irreversibility x agents steered", _rule(),
            f" {'Rank':<6}{'Score':>5}  {'Level':<7}{'Agents':>6}   Untrusted entry -> what it reaches"]
    for i, p in enumerate(ranked, 1):
        reach = f"{p['path'][0]} -> {p['path'][-1]}"
        if p.get("access") and p["access"] != "read":
            reach += f" ({p['access']})"
        out.append(f" {i:<6}{p['score']:>5}  {risk_level(p['score']):<7}{p.get('breadth', 1):>6}   "
                   f"{_clip(reach, WIDTH - 30)}")
    out.append("")

    shown = ranked if top is None else ranked[:top]
    out += [_rule(), f" DETAILS ({len(shown)} of {len(ranked)} paths)", _rule()]
    for i, p in enumerate(shown, 1):
        out.append(f" #{i}  Score {p['score']}  [{risk_level(p['score'])}]   {p.get('reason', '')}")
        out.append(f"     Path : {format_path(p, g)}")
        out.append(_wrap(explain(p, g), 5, label="Why  : "))
        out.append(_wrap(suggest_fix(p, g), 5, label="Fix  : "))
        out.append("")

    if what_if:
        best = what_if[0]
        out += [_rule(), " RECOMMENDED FIRST FIX (simulated)", _rule()]
        out.append(_wrap(f"Make {best['agent']} accept only verified content from {best['resource']} "
                         f"(data_trust \"verified\" on {best['via']}). "
                         f"Re-running the scan with that change, the worst score drops from "
                         f"{best['before']} to {best['after']} "
                         f"({risk_level(best['before'])} -> {risk_level(best['after'])}) and "
                         f"{best['removed']} of {len(ranked)} attack paths disappear.", 1))
        for other in what_if[1:]:
            out.append(f"   Alternative: verify {other['resource']} for {other['agent']}: "
                       f"{other['before']} -> {other['after']}, {other['removed']} paths removed")
        out.append("")

    out.append(_rule("="))
    return "\n".join(out)


def build_comparison(before, after):
    """Side-by-side summary of two scans (e.g. a scenario and its fixed version).

    before / after: (data, paths) tuples.
    """
    def summary(data, paths):
        worst = paths[0]["score"] if paths else 0
        return {"name": data.get("scenario", "?"), "worst": worst, "level": risk_level(worst),
                "paths": len(paths), "cross": sum(1 for p in paths if p.get("breadth", 1) > 1),
                "route": short_path(paths[0]) if paths else "-"}

    b, a = summary(*before), summary(*after)
    drop = 100 * (b["worst"] - a["worst"]) // b["worst"] if b["worst"] else 0
    rows = [("Scenario", b["name"], a["name"]),
            ("Worst score", f"{b['worst']}  [{b['level']}]", f"{a['worst']}  [{a['level']}]"),
            ("Attack paths", b["paths"], a["paths"]),
            ("Cross-agent paths", b["cross"], a["cross"])]
    out = [_rule("="), " BEFORE / AFTER COMPARISON", _rule("="),
           f" {'':<19}{'BEFORE':<29}AFTER"]
    for label, x, y in rows:
        out.append(f" {label:<19}{_clip(str(x), 27):<29}{_clip(str(y), 28)}")
    out += ["", " Worst path before:", f"   {b['route']}", " Worst path after:", f"   {a['route']}", ""]
    if a["worst"] < b["worst"]:
        out.append(_wrap(f"Result: the worst-case blast radius drops by {drop}% "
                         f"({b['worst']} -> {a['worst']}) and {b['paths'] - a['paths']} attack "
                         f"paths disappear.", 1))
    else:
        out.append(f" Result: no improvement ({b['worst']} -> {a['worst']}).")
    out.append(_rule("="))
    return "\n".join(out)


def _clip(text, n):
    return text if len(text) <= n else text[: n - 3] + "..."


def _wrap(text, indent, label=""):
    """Word-wrap to WIDTH after an optional label; continuation lines line up under the text."""
    lines, line = [], " " * indent + label
    for w in text.split():
        if len(line) + len(w) + 1 > WIDTH and line.strip() != label.strip():
            lines.append(line.rstrip())
            line = " " * (indent + len(label))
        line += w + " "
    lines.append(line.rstrip())
    return "\n".join(lines)

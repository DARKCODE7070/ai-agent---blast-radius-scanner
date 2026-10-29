# AI Agent Blast-Radius Scanner

A command-line tool that answers one question for every AI agent in a system:
**"If this agent were compromised (for example by prompt injection), what is the worst it could do?"**

It reads agent descriptions from a JSON file, builds an attack-path graph
(agents, tools, resources, and *trust* between them), finds every path an
attacker could take from untrusted input, scores each one, and prints a ranked
report with a plain-language reason and a suggested fix for every path.

Phase 2 scope: hand-written scenario files only. No real MCP servers, cloud
accounts, ML, or web interface.

## Run it (one command)

```bash
pip install -r requirements.txt
python scanner.py --all
```

`--all` runs every scenario, checks that the scores come out in the right
order, and writes `results/results_table.md`. It exits with code 0 only if every check passes.

Scan one scenario:

```bash
python scanner.py scenarios/03_high_nimbuscart.json
python scanner.py scenarios/03_high_nimbuscart.json --top 3   # details for the 3 worst paths only
```

Before/after a fix (prints both scores side by side):

```bash
python scanner.py scenarios/03_high_nimbuscart.json --compare scenarios/04_nimbuscart_fixed.json
```

Run the tests:

```bash
python -m unittest -v
```

> On Windows, if `python` points at the wrong interpreter, use `py` instead (`py scanner.py --all`).

## The scenarios

| # | File | Shows | Worst score |
|---|---|---|---|
| 1 | `01_low_faq_bot.json` | One agent, read-only, nothing shared. No false alarms. | 2 (LOW) |
| 2 | `02_medium_helpdesk.json` | Two agents share one resource. A real but limited chain. | 12 (MEDIUM) |
| 3 | `03_high_nimbuscart.json` | NimbusCart: prompt injection in Support reaches Inventory's purchase orders through `#ops-alerts`. | 50 (HIGH) |
| 4 | `04_nimbuscart_fixed.json` | Same, but Inventory only accepts verified alerts. | 12 (MEDIUM), 76% lower |
| 5 | `05_nimbuscart_hardened.json` | The hardened NimbusCart tool set from `scenarios.json` (alert drafts, signed alerts, approval-gated orders). | 3 (LOW) |

Full outputs are in [`results/`](results/).

### NimbusCart, the main demo

```
customer_messages  => steers support_agent
                   -- ops.post_alert (write) --> ops_alerts
                   => steers inventory_agent              <- the bridge no permission list shows
                   -- suppliers.place_purchase_order (write) --> supplier_orders
```

The attacker never touches the Inventory agent. Marketing gives a second route into
the same channel, so two paths end at the purchase order. The report's
**Recommended first fix** re-runs the scan with Inventory reading `#ops-alerts` as
`data_trust: "verified"` and shows the worst score dropping from 50 to 12.

### Demo script (about 3 minutes)

1. `python scanner.py scenarios/01_low_faq_bot.json`: a read-only agent scores 2 (LOW). The scanner doesn't raise false alarms.
2. `python scanner.py scenarios/03_high_nimbuscart.json --top 2`: the NimbusCart attack. Point at the two paths scoring 50 and the hop where `inventory_agent` trusts `ops_alerts`.
3. Read the **Recommended first fix** at the bottom: the scanner simulated the fix and predicts 50 -> 12.
4. `python scanner.py scenarios/03_high_nimbuscart.json --top 0 --compare scenarios/04_nimbuscart_fixed.json`: the fix applied. The worst score drops 76% and every cross-agent path disappears.
5. `python scanner.py --all`: all five scenarios, every check PASS.

## Scenario file format

This is the intermediate format defined in `scenarios.json` and `phase2_understanding.json`:
an MCP `tools/list` entry plus a `blast_radius` object. In Phase 3 the adapter and
enrichment steps will produce it from real MCP servers. In Phase 2 it is written by hand.

```json
{
  "scenario": "High risk - NimbusCart",
  "description": "...",
  "expected_level": "HIGH",
  "resources": [
    { "id": "customer_messages", "name": "Inbound customer chat and email" },
    { "id": "ops_alerts", "name": "Shared Slack channel #ops-alerts" }
  ],
  "agents": [
    {
      "name": "support_agent",
      "description": "...",
      "tools": [
        {
          "name": "ops.post_alert",
          "description": "Post an alert to #ops-alerts",
          "inputSchema": { "type": "object" },
          "scopes": ["ops:alerts:write"],
          "blast_radius": { "access": "write", "reaches": "ops_alerts", "data_trust": null,
                            "requires_human_approval": false, "sensitivity": 2, "irreversibility": 2 }
        }
      ]
    }
  ]
}
```

| `blast_radius` field | Meaning |
|---|---|
| `access` | `read` or `write` (`delete` and `execute` are also accepted). Gives the direction of the graph edge. Only a non-read action lets the attacker plant content in a resource. |
| `reaches` | The resource `id` the tool acts on. It must be listed in `resources`. |
| `data_trust` | For read tools: `"untrusted"` = attacker-controlled input (an entry point), `null` / `"unverified"` = the agent acts on whatever is there, `"verified"` = only signed or validated content is accepted, so it cannot carry injected instructions. |
| `requires_human_approval` | `true` if a person must approve the action. The report notes it and won't suggest adding approval again. |
| `sensitivity` | 1-5. How much damage the action can do (1 = public info, 5 = money, secrets, bulk personal data). |
| `irreversibility` | 1-5. How hard the action is to undo (1 = no lasting change, 5 = cannot be undone). |

`inputSchema` and `scopes` are kept from the raw MCP definition but not used by the scanner.
`expected_level` is optional: `--all` checks that the scanner agrees with it.

## How it works

| Stage | File | Owner | Does |
|---|---|---|---|
| 1 | `loader.py` | Role 1 | Loads the JSON, rejects missing fields, unknown resources and out-of-range values, and flattens `blast_radius` into each tool. |
| 2 | `graph_builder.py` | Role 2 | Builds a NetworkX graph: `agent -> tool -> resource`, plus `resource -> agent` for every read whose `data_trust` is not `"verified"`. |
| 3 | `pathfinder.py` | Role 3 | Uses DFS to find every attack path from untrusted entry points, and a Dijkstra-style best-first search for the single worst one. |
| 4 | `report.py`, `scanner.py` | Role 4 | Builds the ranked report, reasons, fixes, what-if fix simulation, CLI, `--all` checks, and tests. |

**Propagation rule.** An attacker who controls a resource steers every agent that
reads it without verification. Through that agent they can use any of its tools.
A resource passes control to the next agent only if the attacker could *write* to it.

**Score** (per path) = `sensitivity x irreversibility x breadth`

* sensitivity and irreversibility come from the path's final action
* breadth = the number of agents the attacker steers along the path

| Level | Score |
|---|---|
| LOW | 1-9 |
| MEDIUM | 10-24 |
| HIGH | 25+ |

**What-if fix.** For every cross-agent trust edge on an attack path, the scanner
switches that read to `data_trust: "verified"`, re-scans, and reports which single
change lowers the worst score the most.

### Handoff contracts between roles

Any stage can be swapped for a teammate's version as long as it keeps these:

* `loader.load_scenario(path)` returns a normalised dict, or raises `loader.ScenarioError`:
  `resources` = `[{id, name, untrusted}]`, `agents` = `[{name, description, tools}]`, and each tool =
  `{name, description, access, reaches, sensitivity, irreversibility, data_trust, requires_human_approval}`.
* `graph_builder.build_graph(data)` returns a `networkx.DiGraph`. Nodes have `kind` = `agent` / `tool` / `resource`. Tool node ids are `"<agent>::<tool>"` with `access`, `sensitivity`, `irreversibility` and `requires_human_approval` attributes. Edge `kind` is `has_tool` / `acts_on` / `trusts` (trust edges carry `via` = the read tool).
* `pathfinder.find_all_paths(g)` returns a list of dicts sorted worst first. `find_worst_path(g)` returns one dict or `None`.
  Keys: `path, score, sensitivity, irreversibility, breadth, agents, entry, target, tool, access, requires_human_approval, reason`.
  `report.build_report` only strictly needs `path`, `score` and `reason`, so it also renders hand-made fake paths.

## Project layout

```
scanner.py          CLI entry point, --all checks, what-if simulation
report.py           ranked report, reasons, fixes
loader.py           JSON loading + validation
graph_builder.py    NetworkX graph
pathfinder.py       DFS + best-first search + scoring
scenarios/                   the Phase 2 scenario files
results/                     saved reports + results_table.md
tests/                       unit tests (python -m unittest -v)
scenarios.json               Role 1 notes: NimbusCart tool set in the intermediate format
phase2_understanding.json    Role 1 notes: raw MCP tools/list -> intermediate format
```

## Phase 3 (planned)

The adapter and enrichment steps (raw MCP `tools/list` -> intermediate JSON, with
`blast_radius` values assigned automatically), cloud/IAM fields on tools
(`cloud_provider`, `iam_role`, `resource_arn`), configurable weights, a graph image
with the worst path in red, and larger generated test graphs.

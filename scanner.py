"""
AI Agent Blast-Radius Scanner - command-line entry point.   (Owner: Role 4)

    python scanner.py scenarios/03_high_nimbuscart.json     scan one scenario
    python scanner.py scenarios/03_high_nimbuscart.json --top 3
    python scanner.py --all                                 run every scenario + checks
    python scanner.py scenarios/03_high_nimbuscart.json --compare scenarios/04_nimbuscart_fixed.json

Pipeline:  loader (Role 1) -> graph_builder (Role 2) -> pathfinder (Role 3) -> report (Role 4)
"""

import argparse
import copy
import glob
import os
import sys

try:
    import networkx  # noqa: F401  (needed by graph_builder and pathfinder)
except ImportError:
    sys.exit("NetworkX is not installed for this Python (" + sys.executable + ").\n"
             "Run:  pip install -r requirements.txt   (on Windows you can also try: py scanner.py ...)")

from loader import ScenarioError, load_scenario
from graph_builder import build_graph
from pathfinder import find_all_paths, find_worst_path
from report import bridges, build_comparison, build_report, explain, risk_level, suggest_fix

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIO_DIR = os.path.join(HERE, "scenarios")
RESULTS_FILE = os.path.join(HERE, "results", "results_table.md")


def scan(data):
    """Run stages 2-3 on loaded data. Returns (graph, ranked paths, worst path)."""
    g = build_graph(data)
    return g, find_all_paths(g), find_worst_path(g)


def simulate_fixes(data, g, paths):
    """What-if mode: for every cross-agent trust edge on an attack path, make the
    agent's read of that resource data_trust "verified", re-scan, and measure the
    new worst score. Best fix first."""
    if not paths:
        return []
    before = paths[0]["score"]
    candidates = {link for p in paths for link in bridges(p, g)}

    results = []
    for resource, agent in sorted(candidates):
        fixed = copy.deepcopy(data)
        for a in fixed["agents"]:
            if a["name"] == agent:
                for t in a["tools"]:
                    if t["access"] == "read" and t["reaches"] == resource:
                        t["data_trust"] = "verified"
        _, new_paths, _ = scan(fixed)
        results.append({
            "resource": resource,
            "agent": agent,
            "via": g.edges[resource, agent]["via"],
            "before": before,
            "after": new_paths[0]["score"] if new_paths else 0,
            "removed": len(paths) - len(new_paths),
        })
    results.sort(key=lambda r: (r["after"], -r["removed"]))
    return results


def scan_file(path, top=None):
    data = load_scenario(path)
    g, paths, worst = scan(data)
    report = build_report(data, paths, worst, g=g, what_if=simulate_fixes(data, g, paths),
                          top=top, source=os.path.relpath(path))
    return data, g, paths, worst, report


# ---------------------------------------------------------------- --all mode

def run_all(directory=SCENARIO_DIR, results_file=RESULTS_FILE):
    """Run every scenario, check the scores are in a sensible order, write the
    results table. Returns True when every check passes."""
    files = sorted(glob.glob(os.path.join(directory, "*.json")))
    rows, checks = [], []

    for f in files:
        name = os.path.basename(f)
        try:
            data, g, paths, worst, _ = scan_file(f)
        except Exception as e:  # report any stage crashing, keep going
            checks.append((f"{name} runs without errors", False, str(e)))
            continue
        checks.append((f"{name} runs without errors", True, ""))
        score = paths[0]["score"] if paths else 0
        level = risk_level(score)
        rows.append({
            "file": name,
            "scenario": data["scenario"],
            "paths": len(paths),
            "cross": sum(1 for p in paths if p["breadth"] > 1),
            "score": score,
            "level": level,
            "expected": data.get("expected_level", "-"),
            "worst": paths[0] if paths else None,
            "agrees": worst is None or worst["score"] == score,
        })
        if "expected_level" in data:
            checks.append((f"{name} level is {data['expected_level']}", level == data["expected_level"],
                           f"got {level}"))
        checks.append((f"{name} best-first search agrees with DFS", rows[-1]["agrees"], ""))
        explained = all(explain(p, g) and suggest_fix(p, g) for p in paths)
        checks.append((f"{name} every path has a reason and a fix", explained, ""))

    by_key = {}
    for r in rows:
        for key in ("low", "medium", "high", "fixed", "hardened"):
            if key in r["file"]:
                by_key[key] = r["score"]
    if {"low", "medium", "high"} <= by_key.keys():
        ok = by_key["low"] < by_key["medium"] < by_key["high"]
        checks.append(("order: low < medium < high", ok,
                       f"{by_key['low']} < {by_key['medium']} < {by_key['high']}"))
    if {"fixed", "high"} <= by_key.keys():
        drop = 100 * (by_key["high"] - by_key["fixed"]) // by_key["high"]
        checks.append(("order: fixed < high (fix works)", by_key["fixed"] < by_key["high"],
                       f"{by_key['high']} -> {by_key['fixed']}, {drop}% lower"))
    if {"hardened", "high"} <= by_key.keys():
        checks.append(("order: hardened < high (Role 1 tool design is safer)",
                       by_key["hardened"] < by_key["high"],
                       f"{by_key['high']} -> {by_key['hardened']}"))

    print(_results_console(rows, checks))
    _write_results_md(rows, checks, results_file)
    print(f"\nResults table written to {os.path.relpath(results_file)}")
    return all(ok for _, ok, _ in checks)


def _results_console(rows, checks):
    out = ["=" * 78, " RESULTS - all scenarios", "=" * 78,
           f" {'Scenario':<30}{'Paths':>6}{'Cross':>7}{'Worst':>7}  {'Level':<8}{'Expected':<9}"]
    for r in rows:
        out.append(f" {r['scenario'][:29]:<30}{r['paths']:>6}{r['cross']:>7}{r['score']:>7}  "
                   f"{r['level']:<8}{r['expected']:<9}")
    out += ["", " CHECKS"]
    for name, ok, detail in checks:
        out.append(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    passed = sum(ok for _, ok, _ in checks)
    out += ["", f" {passed}/{len(checks)} checks passed", "=" * 78]
    return "\n".join(out)


def _write_results_md(rows, checks, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = ["# Phase 2 results", "",
             "Generated by `python scanner.py --all`. "
             "Score = sensitivity x irreversibility x agents steered (worst path).", "",
             "| # | Scenario | Attack paths | Cross-agent | Worst score | Level | Expected | Worst path |",
             "|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        w = r["worst"]
        worst = f"{w['entry']} -> {' -> '.join(w['agents'])} -> {w['tool']}" if w else "-"
        lines.append(f"| {i} | {r['scenario']} | {r['paths']} | {r['cross']} | {r['score']} | "
                     f"{r['level']} | {r['expected']} | `{worst}` |")
    lines += ["", "## Checks", ""]
    for name, ok, detail in checks:
        lines.append(f"- {'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else ""))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------- CLI

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Score the worst-case blast radius of AI agents' tool permissions.")
    parser.add_argument("scenario", nargs="?", help="path to a scenario JSON file")
    parser.add_argument("--all", action="store_true", help="run every file in scenarios/ and check the results")
    parser.add_argument("--top", type=int, metavar="N", help="show details for the N worst paths only")
    parser.add_argument("--compare", metavar="FIXED",
                        help="also scan FIXED (e.g. the scenario after a fix) and print a before/after summary")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    if args.all:
        return 0 if run_all() else 1
    if not args.scenario:
        parser.print_help()
        return 2
    try:
        data, _, paths, _, report = scan_file(args.scenario, top=args.top)
        if args.compare:
            after_data, _, after_paths, _, _ = scan_file(args.compare)
    except ScenarioError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(report)
    if args.compare:
        print()
        print(build_comparison((data, paths), (after_data, after_paths)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

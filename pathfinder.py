"""
Stage 3 - Find attack paths and score them.             (Owner: Role 3)

REFERENCE VERSION written so the pipeline runs end to end. Role 3 can replace
it, as long as these functions keep the same contract:

    find_all_paths(g)  -> list of scored paths, highest score first (DFS)
    find_worst_path(g) -> the single highest-scoring path, or None (best-first search)

A scored path is a dict:
    path          list of node ids: entry, agent, agent::tool, resource, agent, ...
    score         sensitivity * irreversibility * breadth
    sensitivity   of the final action (1-5)
    irreversibility of the final action (1-5, 5 = cannot be undone)
    breadth       number of agents the attacker steers along the path
    agents        those agents, in order
    entry         untrusted resource the attacker controls
    target        resource the final action touches
    tool, access  the final action
    requires_human_approval   whether the final action is gated by a human
    reason        short formula string, e.g. "5 x 5 x 2"

Propagation rule: an attacker who controls a resource steers every agent that
trusts it. Through a steered agent they can use any of its tools. A resource
passes control on to the next agent only if the attacker could write to it
(it is an entry point, or it was reached with a non-read access).
"""

import heapq
import itertools

import networkx as nx


def _score(g, path, agents):
    tool = g.nodes[path[-2]]
    sens, rev, breadth = tool["sensitivity"], tool["irreversibility"], len(agents)
    return {
        "path": list(path),
        "score": sens * rev * breadth,
        "sensitivity": sens,
        "irreversibility": rev,
        "breadth": breadth,
        "agents": list(agents),
        "entry": path[0],
        "target": path[-1],
        "tool": tool["tool"],
        "access": tool["access"],
        "requires_human_approval": tool["requires_human_approval"],
        "reason": f"{sens} x {rev} x {breadth}",
    }


def _entry_points(g):
    return [n for n, d in g.nodes(data=True) if d["kind"] == "resource" and d.get("untrusted")]


def _extensions(g, path, agents):
    """Yield (new_path, new_agents) one hop beyond `path`.

    A path always ends on a resource it controls; one hop = trusting agent -> tool -> resource.
    """
    resource = path[-1]
    for agent in g.successors(resource):              # trust edges
        if agent in agents:
            continue
        for tool in g.successors(agent):
            for target in g.successors(tool):
                if target in path:
                    continue
                yield path + [agent, tool, target], agents + [agent]


def _controls(g, path):
    """True if the attacker can write to the resource at the end of the path."""
    if len(path) == 1:
        return g.nodes[path[0]].get("untrusted", False)
    return g.nodes[path[-2]]["access"] != "read"


def find_all_paths(g):
    """Depth-first search from every untrusted entry point. Returns every attack path, worst first."""
    results = []

    def dfs(path, agents):
        if not _controls(g, path):
            return
        for new_path, new_agents in _extensions(g, path, agents):
            results.append(_score(g, new_path, new_agents))
            dfs(new_path, new_agents)

    for entry in _entry_points(g):
        dfs([entry], [])

    results.sort(key=lambda p: (-p["score"], -p["breadth"], p["path"]))
    return results


def find_worst_path(g):
    """Dijkstra-style best-first search with a max-priority queue.

    Partial paths are expanded in order of an optimistic upper bound on the
    score they could still reach. Once the best bound left in the queue cannot
    beat the best complete path found, the search stops early.
    """
    max_action = max((d["sensitivity"] * d["irreversibility"]
                      for _, d in g.nodes(data=True) if d["kind"] == "tool"), default=0)

    def bound(path, agents):
        # Best score any extension of this path could reach: every agent still
        # reachable from its end gets steered, and the last action is the worst one.
        if not _controls(g, path):
            return 0
        reachable = {n for n in nx.descendants(g, path[-1])
                     if g.nodes[n]["kind"] == "agent" and n not in agents}
        return max_action * (len(agents) + len(reachable)) if reachable else 0

    tie = itertools.count()
    heap = [(-bound([e], []), next(tie), [e], []) for e in _entry_points(g)]
    heapq.heapify(heap)
    best = None

    while heap:
        neg_bound, _, path, agents = heapq.heappop(heap)
        if -neg_bound == 0 or (best and -neg_bound <= best["score"]):
            break
        for new_path, new_agents in _extensions(g, path, agents):
            scored = _score(g, new_path, new_agents)
            if best is None or scored["score"] > best["score"]:
                best = scored
            heapq.heappush(heap, (-bound(new_path, new_agents), next(tie), new_path, new_agents))

    return best

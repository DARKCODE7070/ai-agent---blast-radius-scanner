"""
Stage 2 - Build the attack-path graph.                  (Owner: Role 2)

REFERENCE VERSION written so the pipeline runs end to end. Role 2 can replace
it, as long as build_graph() keeps the same contract:

    build_graph(data) -> networkx.DiGraph      (data = loader.load_scenario output)
    Node ids and attributes:
        "<agent>"            kind="agent"
        "<resource id>"      kind="resource", untrusted=bool, label
        "<agent>::<tool>"    kind="tool", agent, tool, access, sensitivity,
                             irreversibility, requires_human_approval
    Edges:
        agent    -> tool       kind="has_tool"
        tool     -> resource   kind="acts_on", access
        resource -> agent      kind="trusts", via=<read tool>
                               for every read tool whose data_trust is not "verified":
                               the agent acts on what it reads, so whoever can write
                               that resource can steer the agent.
"""

import networkx as nx


def tool_node(agent_name, tool_name):
    return f"{agent_name}::{tool_name}"


def build_graph(data):
    g = nx.DiGraph()

    for r in data["resources"]:
        g.add_node(r["id"], kind="resource", untrusted=r["untrusted"], label=r["name"])

    for a in data["agents"]:
        g.add_node(a["name"], kind="agent", description=a["description"])

        for t in a["tools"]:
            tid = tool_node(a["name"], t["name"])
            g.add_node(tid, kind="tool", agent=a["name"], tool=t["name"], access=t["access"],
                       sensitivity=t["sensitivity"], irreversibility=t["irreversibility"],
                       requires_human_approval=t["requires_human_approval"])
            g.add_edge(a["name"], tid, kind="has_tool")
            g.add_edge(tid, t["reaches"], kind="acts_on", access=t["access"])

            if t["access"] == "read" and t["data_trust"] != "verified":
                g.add_edge(t["reaches"], a["name"], kind="trusts", via=t["name"])

    return g

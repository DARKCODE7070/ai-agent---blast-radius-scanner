"""
Draws the agent graph and highlights the highest-scoring attack path in red.

Put this file in the same folder as attack_path.py and graph_builder.py.
Then run:   python visualize_worst_path.py
"""
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.lines import Line2D

# Scoring file: attack_path.py
import attack_path as scorer   # must expose: graph, attack_paths, attack_path_scoring


EDGE_COLORS = {
    "untrusted": "#d62728",   # attacker-controlled text enters here
    "verified": "#2ca02c",    # checked / trusted source
    "write": "#1f77b4",       # agent pushes data OUT to a resource
    "other": "#7f7f7f",       # data_trust is null
}


def _edge_kind(attrs):
    if attrs.get("access") == "write":
        return "write"
    trust = attrs.get("data_trust")
    return "other" if trust in (None, "null") else trust


def find_worst_path(G, attack_paths, score_fn, only_untrusted_entry=False):
    """
    attack_paths is a list of groups; each group is a list of edge-paths
    (one group per source->target resource pair). Flatten, score every
    path, and return (best_path, best_score, all_scored).

    Set only_untrusted_entry=True to keep only paths that START at an
    untrusted read.
    """
    flat = [p for group in attack_paths for p in group]
    if only_untrusted_entry:
        flat = [p for p in flat
                if G.edges[p[0]].get("data_trust") == "untrusted"]
    scored = sorted(((score_fn(p), p) for p in flat),
                    key=lambda t: t[0], reverse=True)
    if not scored:
        return None, 0, []
    return scored[0][1], scored[0][0], scored


COL_GAP = 3.6   # horizontal distance between layers


def _layout(G):
    """
    Left-to-right layers, so data flows across the page and edges rarely cross.
    Returns (positions, layered). Falls back to a spring layout if the graph
    has a loop (an agent that reads and writes the same chain), where clean
    layers are impossible.
    """
    try:
        gens = list(nx.topological_generations(G))
    except nx.NetworkXUnfeasible:
        return nx.spring_layout(G, seed=42, k=2.0), False

    layer = {n: i for i, gen in enumerate(gens) for n in gen}
    isolated = [n for n in G if G.degree(n) == 0]
    for n in G:   # pull pure sources right up next to their first consumer
        if G.in_degree(n) == 0 and G.out_degree(n) > 0:
            layer[n] = min(layer[s] for s in G.successors(n)) - 1

    columns = {}
    for n, i in layer.items():
        if n not in isolated:
            columns.setdefault(i, []).append(n)

    def column_y(nodes):
        return [((len(nodes) - 1) / 2 - i) * 2.6 for i in range(len(nodes))]

    pos = {}
    for x in sorted(columns):      # order each column by where its inputs sit
        def mean_y(n):
            ys = [pos[p][1] for p in G.predecessors(n) if p in pos]
            return sum(ys) / len(ys) if ys else 0
        nodes = sorted(columns[x], key=lambda n: (-mean_y(n), n))
        for n, y in zip(nodes, column_y(nodes)):
            pos[n] = (x * COL_GAP, y)

    for x in sorted(columns):      # re-order pure sources by where they feed
        srcs = [n for n in columns[x] if G.in_degree(n) == 0]
        if len(srcs) > 1:
            slots = sorted((pos[n][1] for n in srcs), reverse=True)
            srcs.sort(key=lambda n: -sum(pos[s][1] for s in G.successors(n))
                      / max(G.out_degree(n), 1))
            for n, y in zip(srcs, slots):
                pos[n] = (pos[n][0], y)

    if isolated:                   # unreachable resources get their own column
        x = (max(columns) + 1) * COL_GAP
        for n, y in zip(sorted(isolated), column_y(isolated)):
            pos[n] = (x, y)
    return pos, True


def visualize_graph(G, highlight_path=None, score=None,
                    title="Agent blast-radius graph", save_to=None):
    """
    highlight_path: list of (u, v, key) edge tuples, exactly what
                    nx.all_simple_edge_paths returns. Drawn thick and red,
                    numbered in order. Everything else is faded.
    """
    pos, layered = _layout(G)
    fig, ax = plt.subplots(figsize=(15, 9))

    hl_edges = {tuple(e) for e in (highlight_path or [])}
    hl_nodes = {n for e in hl_edges for n in e[:2]}
    step_of = {tuple(e): i + 1 for i, e in enumerate(highlight_path or [])}
    fade = 0.35 if highlight_path else 1.0

    agents = [n for n, d in G.nodes(data=True) if d.get("type") == "agent"]
    resources = [n for n, d in G.nodes(data=True) if d.get("type") != "agent"]

    for nodes, shape, color in ((agents, "s", "#aec7e8"),
                                (resources, "o", "#ffdd99")):
        nx.draw_networkx_nodes(
            G, pos, nodelist=nodes, node_shape=shape, node_color=color,
            edgecolors=["red" if n in hl_nodes else "black" for n in nodes],
            linewidths=[3.5 if n in hl_nodes else 1 for n in nodes],
            node_size=3200, ax=ax)
    nx.draw_networkx_labels(G, pos, labels={n: n.replace("_", "\n") for n in G},
                            font_size=7, font_weight="bold", ax=ax)

    # group parallel edges so they fan out instead of overlapping
    for u, v in {(u, v) for u, v, _ in G.edges(keys=True)}:
        keys = list(G[u][v].keys())
        n = len(keys)
        for i, k in enumerate(keys):
            attrs = G[u][v][k]
            span = abs(pos[v][0] - pos[u][0])
            base = 0.25 if (not layered or span > COL_GAP * 1.1) else 0.0
            rad = base + 0.25 * (i - (n - 1) / 2)
            on_path = (u, v, k) in hl_edges

            nx.draw_networkx_edges(
                G, pos, edgelist=[(u, v, k)], ax=ax,
                edge_color="red" if on_path
                else EDGE_COLORS.get(_edge_kind(attrs), "#7f7f7f"),
                width=4.5 if on_path else 1.6,
                alpha=1.0 if on_path else fade,
                arrows=True, arrowsize=20 if on_path else 14,
                node_size=3000, connectionstyle=f"arc3,rad={rad}")

            if attrs.get("tool_name"):
                (x1, y1), (x2, y2) = pos[u], pos[v]
                # point on the curve; long arcs get their label near the
                # arrowhead so it stays clear of edges they cross
                t = 0.7 if (layered and span > COL_GAP * 1.1) else 0.5
                cx = (x1 + x2) / 2 + rad * (y2 - y1)
                cy = (y1 + y2) / 2 - rad * (x2 - x1)
                mx = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cx + t ** 2 * x2
                my = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cy + t ** 2 * y2
                label = attrs["tool_name"]
                if on_path:
                    label = f"{step_of[(u, v, k)]}. {label}"
                ax.text(mx, my, label, fontsize=7 if on_path else 6,
                        fontweight="bold" if on_path else "normal",
                        color="red" if on_path else "black",
                        alpha=1.0 if on_path else max(fade, 0.6),
                        ha="center", va="center",
                        bbox=dict(boxstyle="round,pad=0.15", fc="white",
                                  ec="red" if on_path else "none", alpha=0.9))

    legend = [
        Line2D([0], [0], marker="s", color="w", markerfacecolor="#aec7e8",
               markeredgecolor="black", markersize=12, label="Agent"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor="#ffdd99",
               markeredgecolor="black", markersize=12, label="Resource"),
        Line2D([0], [0], color=EDGE_COLORS["untrusted"], lw=2, label="read, untrusted"),
        Line2D([0], [0], color=EDGE_COLORS["verified"], lw=2, label="read, verified"),
        Line2D([0], [0], color=EDGE_COLORS["write"], lw=2, label="write"),
    ]
    if highlight_path:
        legend.append(Line2D([0], [0], color="red", lw=5,
                             label="worst-case damage path"))
    fig.legend(handles=legend, loc="lower center", ncol=len(legend), fontsize=8)

    if score is not None:
        title += f"   (worst path score: {score:.2f})"
    ax.set_title(title, fontsize=13)
    ax.set_aspect("equal")   # keeps curved edges and their labels lined up
    ax.axis("off")
    ax.margins(0.08)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    if save_to:
        fig.savefig(save_to, dpi=200, bbox_inches="tight")
    plt.show()


if __name__ == "__main__":
    G = scorer.graph
    worst, score, scored = find_worst_path(
        G, scorer.attack_paths, scorer.attack_path_scoring)

    if worst is None:
        print("No attack paths found.")
        visualize_graph(G, title="No attack paths found")
    else:
        print(f"\nWorst path (score {score:.2f}):")
        for u, v, k in worst:
            print(f"  {u} -> {v}   via {G.edges[u, v, k]['tool_name']}")
        ties = [p for s, p in scored if abs(s - score) < 1e-9 and p != worst]
        if ties:
            print(f"({len(ties)} other path(s) tie with this score)")
        visualize_graph(G, highlight_path=worst, score=score,
                        title="NimbusCart (vulnerable)", save_to="worst_path.png")
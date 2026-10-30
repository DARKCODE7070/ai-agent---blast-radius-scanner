import networkx as nx
from graph_builder import build_agent_graph
import json

##recongifure the path finding and scoring for resource chaining - el phase 3

with open("case.json","r",encoding = "utf-8") as file:
    data = json.load(file)

graph = build_agent_graph(data)

resource_nodes = []
agent_nodes = []
attack_paths = []

for node,type in graph.nodes(data = "type"):
    if type == "resource":
        resource_nodes.append(node)
    elif type == "agent":
        agent_nodes.append(node)

for source in resource_nodes:
    for target in resource_nodes:
        if(nx.has_path(G = graph, source = source, target = target) and source != target):
            path = nx.all_simple_edge_paths(G = graph, source = source, target = target)
            # This uses DFS, but is very exhaustive
            # hence we use has_path to check if path exists or not, this uses bfs under the hood which is much more efficient
            path = list(path)
            attack_paths.append(list(path))
            print(path)

            # modify to only have unverified or sensitive resources as source later

def attack_path_scoring(path):
    target_resource_attributes = graph.edges[*path[-1]]
    sensitivity = target_resource_attributes["sensitivity"]
    irreversibility = target_resource_attributes["irreversibility"]
    impact = sensitivity * irreversibility
    likelihood = 1
    trust = True

    for edge in path:
        edge_attributes = graph.edges[*edge]
        if edge_attributes["requires_human_approval"]:
            likelihood *= 0.5
        else:
            likelihood *= 0.75
        if edge_attributes["data_trust"] == "untrusted" and trust:
            trust = False

    trust_score = 1 if trust else 2.25
    score = (likelihood * trust_score) * impact
    return score

attack_path_scores = [attack_path_scoring(path[0]) for path in attack_paths]
print(attack_path_scores)




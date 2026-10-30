import networkx as nx
from graph_builder import build_agent_graph

##recongifure the path finding and scoring for resource chaining - el phase 3
def attack_path_finder(graph):

    resource_nodes = []
    agent_nodes = []
    attack_paths = {}

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
                
                attack_paths[f"{source} -> {target}"]  = {
                    "paths" : list(path)
                }
    return attack_paths

                # modify to only have unverified or sensitive resources as source later

def attack_path_scorer(graph,path):
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
    return round(score,4)

if __name__ == "__main__":
    import json, sys
    try:
        schema_file = sys.argv[1]
    except IndexError:
        schema_file = "case.json"

    with open(schema_file,"r",encoding = "utf-8") as file:
        data = json.load(file)

    graph = build_agent_graph(data)

    attack_paths = attack_path_finder(graph)

    attack_paths_scores = []
    for item in attack_paths.values():
        for path in item["paths"]:
            attack_paths_scores.append(attack_path_scorer(graph,path))
        item["scores"] = attack_paths_scores

    print(f"The attack paths and scores are {attack_paths}\n")
    




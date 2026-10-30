import networkx as nx

def build_agent_graph(data: dict) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()
    
    resources = data.get("resources", [])
    for resource in resources:
        res_id = resource.get("id")
        res_name = resource.get("name")
        if res_id:
            G.add_node(res_id, type="resource", name=res_name)
        
    agents = data.get("agents", [])
    for agent in agents:
        agent_id = agent["name"]
        G.add_node(agent_id, type="agent")
        
        for tool in agent.get("tools", []):
            blast_radius = tool.get("blast_radius", {})
            target_resource = blast_radius.get("reaches")
            
            if not target_resource:
                continue
                
            if not G.has_node(target_resource):
                G.add_node(target_resource, type="resource", name=target_resource)
                
            access = blast_radius.get("access")
            data_trust = blast_radius.get("data_trust")
            
            if access == "write":
                source, target = agent_id, target_resource
            elif access == "read":
                source, target = target_resource, agent_id
            else:
                source, target = agent_id, target_resource
            
            G.add_edge(
                source,
                target,
                tool_name=tool.get("name"),
                access=access,
                sensitivity=blast_radius.get("sensitivity"),
                irreversibility=blast_radius.get("irreversibility"),
                requires_human_approval=blast_radius.get("requires_human_approval"),
                data_trust=data_trust
            )
            
    return G
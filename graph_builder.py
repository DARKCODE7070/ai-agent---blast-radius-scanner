import networkx as nx

def build_agent_graph(data: dict) -> nx.MultiDiGraph:
    """
    Constructs a NetworkX MultiDiGraph from Role 1's validated data schema.
    Edge direction depends on access type:
      - 'write': agent -> resource
      - 'read': resource -> agent
    """
    G = nx.MultiDiGraph()
    
    # 1. Add all resource nodes
    resources = data.get("resources", [])
    for resource in resources:
        res_id = resource.get("id")
        res_name = resource.get("name")
        if res_id:
            G.add_node(res_id, type="resource", name=res_name)
        
    # 2. Add all agent nodes
    agents = data.get("agents", [])
    for agent in agents:
        agent_id = agent["name"]
        G.add_node(agent_id, type="agent")
        
        # 3. Process each tool associated with the agent
        for tool in agent.get("tools", []):
            blast_radius = tool.get("blast_radius", {})
            target_resource = blast_radius.get("reaches")
            
            # Skip if the tool doesn't reach a resource
            if not target_resource:
                continue
                
            # Fallback safeguard: ensure target resource exists as a node
            if not G.has_node(target_resource):
                G.add_node(target_resource, type="resource", name=target_resource)
                
            access = blast_radius.get("access")
            data_trust = blast_radius.get("data_trust")
            
            # Determine edge direction based on access type
            if access == "write":
                source, target = agent_id, target_resource
            elif access == "read":
                source, target = target_resource, agent_id
            else:
                # Default fallback if access type is unspecified
                source, target = agent_id, target_resource
            
            # Add the directed edge carrying all necessary scoring attributes
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
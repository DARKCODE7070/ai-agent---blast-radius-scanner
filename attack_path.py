import networkx as nx
from graph_builder import build_agent_graph

##recongifure the path finding and scoring for resource chaining - el phase 3

graph = build_agent_graph({
  "scenario": "High risk - NimbusCart",
  "description": "Support and Marketing both post to the shared #ops-alerts channel. Inventory trusts that channel and can place real supplier purchase orders, so a prompt-injected message reaches money.",
  "expected_level": "HIGH",
  "resources": [
    {
      "id": "customer_messages",
      "name": "Inbound customer chat and email"
    },
    {
      "id": "social_mentions",
      "name": "Public social-media replies the marketing agent monitors"
    },
    {
      "id": "orders_db",
      "name": "Customer orders"
    },
    {
      "id": "ops_alerts",
      "name": "Shared Slack channel #ops-alerts"
    },
    {
      "id": "inventory_db",
      "name": "Stock levels per SKU"
    },
    {
      "id": "supplier_catalog",
      "name": "Approved supplier catalogues"
    },
    {
      "id": "supplier_orders",
      "name": "Real purchase orders sent to suppliers"
    },
    {
      "id": "promotions",
      "name": "Live store promotions and discounts"
    }
  ],
  "agents": [
    {
      "name": "support_agent",
      "description": "Reads customer messages, looks up orders, can post to #ops-alerts",
      "tools": [
        {
          "name": "support.read_customer_message",
          "description": "",
          "blast_radius": {
            "access": "read",
            "reaches": "customer_messages",
            "data_trust": "untrusted",
            "requires_human_approval": False,
            "sensitivity": 1,
            "irreversibility": 1
          }
        },
        {
          "name": "orders.lookup_order",
          "description": "",
          "blast_radius": {
            "access": "read",
            "reaches": "orders_db",
            "data_trust": "verified",
            "requires_human_approval": False,
            "sensitivity": 3,
            "irreversibility": 1
          }
        },
        {
          "name": "ops.post_alert",
          "description": "",
          "blast_radius": {
            "access": "write",
            "reaches": "ops_alerts",
            "data_trust": None,
            "requires_human_approval": False,
            "sensitivity": 2,
            "irreversibility": 2
          }
        }
      ]
    },
    {
      "name": "inventory_agent",
      "description": "Reads #ops-alerts, trusts it, and can place real supplier purchase orders",
      "tools": [
        {
          "name": "ops.read_alerts",
          "description": "",
          "blast_radius": {
            "access": "read",
            "reaches": "ops_alerts",
            "data_trust": None,
            "requires_human_approval": False,
            "sensitivity": 2,
            "irreversibility": 1
          }
        },
        {
          "name": "inventory.check_stock",
          "description": "",
          "blast_radius": {
            "access": "read",
            "reaches": "inventory_db",
            "data_trust": "verified",
            "requires_human_approval": False,
            "sensitivity": 2,
            "irreversibility": 1
          }
        },
        {
          "name": "suppliers.search_catalog",
          "description": "",
          "blast_radius": {
            "access": "read",
            "reaches": "supplier_catalog",
            "data_trust": "verified",
            "requires_human_approval": False,
            "sensitivity": 1,
            "irreversibility": 1
          }
        },
        {
          "name": "suppliers.place_purchase_order",
          "description": "",
          "blast_radius": {
            "access": "write",
            "reaches": "supplier_orders",
            "data_trust": None,
            "requires_human_approval": False,
            "sensitivity": 5,
            "irreversibility": 5
          }
        }
      ]
    },
    {
      "name": "marketing_agent",
      "description": "Runs promotions and can also post to #ops-alerts",
      "tools": [
        {
          "name": "social.read_mentions",
          "description": "Read public social-media replies and mentions.",
          "blast_radius": {
            "access": "read",
            "reaches": "social_mentions",
            "data_trust": "untrusted",
            "requires_human_approval": False,
            "sensitivity": 1,
            "irreversibility": 1
          }
        },
        {
          "name": "marketing.create_promotion",
          "description": "",
          "blast_radius": {
            "access": "write",
            "reaches": "promotions",
            "data_trust": None,
            "requires_human_approval": False,
            "sensitivity": 4,
            "irreversibility": 3
          }
        },
        {
          "name": "ops.post_alert",
          "description": "",
          "blast_radius": {
            "access": "write",
            "reaches": "ops_alerts",
            "data_trust": None,
            "requires_human_approval": False,
            "sensitivity": 2,
            "irreversibility": 2
          }
        }
      ]
    }
  ]
})

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

    for edge in path:
        edge_attributes = graph.edges[*edge]
        if edge_attributes["requires_human_approval"]:
            likelihood *= 0.5
        else:
            likelihood *= 0.75

    score = likelihood * impact
    return score

attack_path_scores = [attack_path_scoring(path[0]) for path in attack_paths]
print(attack_path_scores)




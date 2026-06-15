import networkx as nx
import random
from dataclasses import dataclass
from typing import Optional


#node types 

MACHINE_ROLES = ["workstation", "server", "domain_controller", "database", "web_server", "firewall"]
USER_ROLES    = ["admin", "user", "service_account"]
SERVICE_TYPES = ["SSH", "RDP", "HTTP", "SMB", "FTP", "MSSQL", "MySQL"]
EDGE_TYPES    = ["CONNECTS_TO", "HAS_SERVICE", "HAS_VULN", "CAN_ACCESS"]


#node dataclasses 
@dataclass
class MachineNode:
    node_id: str
    role: str
    os: str = "Windows"
    ip: str = "10.0.0.1"

    def to_dict(self):
        return {"type": "Machine", "role": self.role, "os": self.os, "ip": self.ip}


@dataclass
class UserNode:
    node_id: str
    role: str
    username: str = ""

    def to_dict(self):
        return {"type": "User", "role": self.role, "username": self.username}


@dataclass
class ServiceNode:
    node_id: str
    service_type: str
    port: int = 80

    def to_dict(self):
        return {"type": "Service", "service_type": self.service_type, "port": self.port}


@dataclass
class VulnerabilityNode:
    node_id: str
    cvss: float
    exploit_type: str
    privilege_impact: str

    def to_dict(self):
        return {"type": "Vulnerability", "cvss": self.cvss, "exploit_type": self.exploit_type, "privilege_impact": self.privilege_impact}



#building the graph

def build_network(n_machines: int = 10, n_users: int = 5, seed: Optional[int] = 42) -> nx.DiGraph:
    if seed is not None:
        random.seed(seed)

    G = nx.DiGraph()

    G.add_node("ATTACKER", type="Attacker", role="attacker")

    machines = []
    for i in range(n_machines):
        node_id = f"M{i:02d}"
        m = MachineNode(node_id=node_id, role=random.choice(MACHINE_ROLES),
                        os=random.choice(["Windows", "Linux"]), ip=f"10.0.0.{i+10}")
        G.add_node(node_id, **m.to_dict())
        machines.append(node_id)

    users = []
    for i in range(n_users):
        node_id = f"U{i:02d}"
        u = UserNode(node_id=node_id, role=random.choice(USER_ROLES), username=f"user_{i:02d}")
        G.add_node(node_id, **u.to_dict())
        users.append(node_id)

    for m_id in machines:
        svc_id = f"SVC_{m_id}"
        s = ServiceNode(node_id=svc_id, service_type=random.choice(SERVICE_TYPES),
                        port=random.choice([22, 80, 443, 445, 3306, 3389, 1433]))
        G.add_node(svc_id, **s.to_dict())
        G.add_edge(m_id, svc_id, edge_type="HAS_SERVICE")

    vuln_machines = random.sample(machines, k=max(1, n_machines // 2))
    for m_id in vuln_machines:
        vuln_id = f"VULN_{m_id}"
        v = VulnerabilityNode(node_id=vuln_id, cvss=round(random.uniform(4.0, 10.0), 1),
                              exploit_type=random.choice(["RCE", "SQLi", "XSS", "PrivEsc", "BufferOverflow"]),
                              privilege_impact=random.choice(["none", "low", "high"]))
        G.add_node(vuln_id, **v.to_dict())
        G.add_edge(m_id, vuln_id, edge_type="HAS_VULN")

    for m_id in machines:
        targets = random.sample([m for m in machines if m != m_id], k=min(3, len(machines)-1))
        for t in targets:
            G.add_edge(m_id, t, edge_type="CONNECTS_TO")

    for u_id in users:
        targets = random.sample(machines, k=min(3, len(machines)))
        for t in targets:
            G.add_edge(u_id, t, edge_type="CAN_ACCESS")

    for ep in machines[:2]:
        G.add_edge("ATTACKER", ep, edge_type="CONNECTS_TO")

    return G


#summarizing our work

def print_graph_summary(G: nx.DiGraph):
    print("\n" + "═"*50)
    print("  ATPS — Network Graph Summary")
    print("═"*50)

    type_counts = {}
    for _, data in G.nodes(data=True):
        t = data.get("type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"\n  Total nodes : {G.number_of_nodes()}")
    print(f"  Total edges : {G.number_of_edges()}")
    print(f"\n  Node breakdown:")
    for t, count in sorted(type_counts.items()):
        print(f"    {t:<20} {count}")

    edge_type_counts = {}
    for _, _, data in G.edges(data=True):
        et = data.get("edge_type", "Unknown")
        edge_type_counts[et] = edge_type_counts.get(et, 0) + 1

    print(f"\n  Edge breakdown:")
    for et, count in sorted(edge_type_counts.items()):
        print(f"    {et:<20} {count}")

    print("\n" + "═"*50 + "\n")


if __name__ == "__main__":
    G = build_network(n_machines=10, n_users=5, seed=42)
    print_graph_summary(G)
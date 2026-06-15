import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import networkx as nx
import random
from graph_builder import (
    build_network,
    print_graph_summary,
    MACHINE_ROLES, USER_ROLES, SERVICE_TYPES
)


def generate_network(n_machines=10, n_users=5, seed=42):
    assert n_machines >= 2, "Need at least 2 machines"
    assert n_users >= 1,    "Need at least 1 user"

    print(f"\n[+] Generating network (machines={n_machines}, users={n_users}, seed={seed})")
    G = build_network(n_machines=n_machines, n_users=n_users, seed=seed)

    G.graph["seed"]       = seed
    G.graph["n_machines"] = n_machines
    G.graph["n_users"]    = n_users

    return G


def get_nodes_by_type(G, node_type):
    return [n for n, d in G.nodes(data=True) if d.get("type") == node_type]


def get_admin_users(G):
    return [n for n, d in G.nodes(data=True)
            if d.get("type") == "User" and d.get("role") == "admin"]


def get_high_value_machines(G):
    return [n for n, d in G.nodes(data=True)
            if d.get("type") == "Machine" and d.get("role") in ["domain_controller", "database"]]


def print_network_roles(G):
    print("\n  Machine roles:")
    for n in get_nodes_by_type(G, "Machine"):
        d = G.nodes[n]
        print(f"    {n:<8} {d['role']:<20} {d['os']:<10} {d['ip']}")

    print("\n  User roles:")
    for n in get_nodes_by_type(G, "User"):
        d = G.nodes[n]
        print(f"    {n:<8} {d['role']:<20} {d['username']}")

    print("\n  High value targets:")
    hvt = get_high_value_machines(G)
    if hvt:
        for n in hvt:
            print(f"    {n} — {G.nodes[n]['role']}")
    else:
        print("    none identified")

    print("\n  Admin users:")
    admins = get_admin_users(G)
    if admins:
        for n in admins:
            print(f"    {n} — {G.nodes[n]['username']}")
    else:
        print("    none identified")


if __name__ == "__main__":
    G1 = generate_network(n_machines=10, n_users=5, seed=42)
    print_graph_summary(G1)
    print_network_roles(G1)

    G2 = generate_network(n_machines=20, n_users=10, seed=99)
    print_graph_summary(G2)
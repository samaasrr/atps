import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import networkx as nx
from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities, get_vulnerability_report


def find_all_paths_bfs(G, start="ATTACKER", max_depth=6):
    """
    BFS-based path finder. Finds all simple paths from start
    to every other reachable node, up to max_depth.
    """
    all_paths = []
    queue = [(start, [start])]

    while queue:
        current, path = queue.pop(0)

        if len(path) > max_depth:
            continue

        # record this path if it has more than just the start node
        if len(path) > 1:
            all_paths.append(path)

        for neighbor in G.successors(current):
            if neighbor not in path:  # prevent cycles
                queue.append((neighbor, path + [neighbor]))

    return all_paths


def find_all_paths_dfs(G, start="ATTACKER", max_depth=6):
    """
    DFS-based full path explorer, bounded by max_depth.
    Returns every simple path from start node.
    """
    all_paths = []

    def dfs(current, path):
        if len(path) > max_depth:
            return

        if len(path) > 1:
            all_paths.append(list(path))

        for neighbor in G.successors(current):
            if neighbor not in path:
                path.append(neighbor)
                dfs(neighbor, path)
                path.pop()

    dfs(start, [start])
    return all_paths


def get_machine_only_paths(G, paths):
    """
    Filter paths down to only those that end on a Machine node
    (i.e. actual attack targets, not services/vulns).
    """
    machine_paths = []
    for path in paths:
        end_node = path[-1]
        if G.nodes[end_node].get("type") == "Machine":
            machine_paths.append(path)
    return machine_paths


def print_path_summary(paths, label="All Paths"):
    print(f"\n  {label}: {len(paths)} found")
    if not paths:
        print("    none")
        return

    # show a few examples
    print("  Sample paths:")
    for path in paths[:10]:
        print(f"    {' → '.join(path)}  (length {len(path)-1})")

    lengths = [len(p) - 1 for p in paths]
    print(f"\n  Shortest path length : {min(lengths)}")
    print(f"  Longest path length  : {max(lengths)}")


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    bfs_paths = find_all_paths_bfs(G, max_depth=6)
    print_path_summary(bfs_paths, label="BFS — All Paths")

    machine_paths = get_machine_only_paths(G, bfs_paths)
    print_path_summary(machine_paths, label="BFS — Machine-Only Paths")
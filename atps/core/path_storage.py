import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from path_finder import find_all_paths_bfs, get_machine_only_paths


def path_to_dict(G, path):
    return {
        "path": path,
        "length": len(path) - 1,
        "hops": [
            {
                "node": node,
                "type": G.nodes[node].get("type", "Unknown"),
                "role": G.nodes[node].get("role", None),
                "cvss": G.nodes[node].get("cvss", None),
            }
            for node in path
        ]
    }


def build_path_dataset(G, paths):
    return [path_to_dict(G, p) for p in paths]


def save_paths_to_json(path_data, filename="attack_paths.json"):
    output = {
        "generated_at": datetime.now().isoformat(),
        "total_paths": len(path_data),
        "paths": path_data
    }

    os.makedirs("output", exist_ok=True)
    filepath = os.path.join("output", filename)

    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[+] Saved {len(path_data)} paths to {filepath}")
    return filepath


def load_paths_from_json(filepath):
    with open(filepath, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    bfs_paths = find_all_paths_bfs(G, max_depth=6)
    machine_paths = get_machine_only_paths(G, bfs_paths)

    path_data = build_path_dataset(G, machine_paths)
    filepath = save_paths_to_json(path_data)

    # quick check basically we load it back and print first entry
    loaded = load_paths_from_json(filepath)
    print(f"\n[+] Verification — loaded {loaded['total_paths']} paths back from disk")
    print(json.dumps(loaded["paths"][0], indent=2))
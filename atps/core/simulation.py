import sys
import os
import random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from path_scoring import score_path


def simulate_attacker(G, strategy_name, start="ATTACKER", max_steps=6):
    current = start
    path = [current]
    visited = {current}
    log = []

    for step in range(max_steps):
        neighbors = [n for n in G.successors(current) if n not in visited]
        if not neighbors:
            break

        machines = [n for n in neighbors if G.nodes[n].get("type") == "Machine"]
        candidates = machines if machines else neighbors

        scored_candidates = []
        for c in candidates:
            test_path = path + [c]
            result = score_path(G, test_path)
            scored_candidates.append((c, result["score"]))

        if strategy_name == "highest_cvss":
            next_node = max(scored_candidates, key=lambda x: x[1])[0]
        elif strategy_name == "lowest_cvss":
            next_node = min(scored_candidates, key=lambda x: x[1])[0]
        elif strategy_name == "random":
            next_node = random.choice(candidates)
        else:
            raise ValueError(f"unknown strategy: {strategy_name}")

        log.append({
            "step": step,
            "from": current,
            "to": next_node,
            "candidates": candidates,
            "chosen_score": dict(scored_candidates).get(next_node),
        })

        path.append(next_node)
        visited.add(next_node)
        current = next_node

    return path, log


def print_simulation(strategy_name, path, log):
    print(f"\n{strategy_name}:")
    print(f"  path: {' -> '.join(path)}")
    for entry in log:
        print(f"  step {entry['step']}: {entry['from']} -> {entry['to']} (score {entry['chosen_score']})")


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    for strategy in ["highest_cvss", "lowest_cvss", "random"]:
        path, log = simulate_attacker(G, strategy)
        print_simulation(strategy, path, log)
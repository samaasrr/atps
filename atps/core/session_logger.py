import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from path_scoring import score_path


def simulate_with_full_log(G, strategy_name, start="ATTACKER", max_steps=6):
    current = start
    path = [current]
    visited = {current}
    session = {
        "strategy": strategy_name,
        "started_at": datetime.now().isoformat(),
        "start_node": start,
        "steps": [],
    }

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
            scored_candidates.append({"node": c, "score": result["score"]})

        if strategy_name == "highest_cvss":
            chosen = max(scored_candidates, key=lambda x: x["score"])
        elif strategy_name == "lowest_cvss":
            chosen = min(scored_candidates, key=lambda x: x["score"])
        elif strategy_name == "random":
            import random
            chosen = random.choice(scored_candidates)
        else:
            raise ValueError(f"unknown strategy: {strategy_name}")

        rejected = [c for c in scored_candidates if c["node"] != chosen["node"]]

        session["steps"].append({
            "step": step,
            "from": current,
            "chosen": chosen["node"],
            "chosen_score": chosen["score"],
            "candidates": scored_candidates,
            "rejected": rejected,
        })

        path.append(chosen["node"])
        visited.add(chosen["node"])
        current = chosen["node"]

    session["final_path"] = path
    session["ended_at"] = datetime.now().isoformat()
    session["total_steps"] = len(session["steps"])

    return session


def save_session(session, filename=None):
    os.makedirs("output/sessions", exist_ok=True)
    if filename is None:
        filename = f"session_{session['strategy']}.json"
    filepath = os.path.join("output/sessions", filename)

    with open(filepath, "w") as f:
        json.dump(session, f, indent=2)

    return filepath


def print_session_summary(session):
    print(f"\n{session['strategy']}:")
    print(f"  final path: {' -> '.join(session['final_path'])}")
    print(f"  total steps: {session['total_steps']}")
    for step in session["steps"]:
        n_rejected = len(step["rejected"])
        print(f"  step {step['step']}: chose {step['chosen']} (score {step['chosen_score']}), rejected {n_rejected} other option(s)")


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    for strategy in ["highest_cvss", "lowest_cvss", "random"]:
        session = simulate_with_full_log(G, strategy)
        print_session_summary(session)
        filepath = save_session(session)
        print(f"  saved to {filepath}")
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from session_logger import simulate_with_full_log


def compare_sessions(sessions):
    print(f"\n{'Strategy':<15}{'Steps':<8}{'AvgCVSS':<10}{'Unique Targets':<16}{'TotalRejected'}")
    print("-" * 65)

    for session in sessions:
        strategy = session["strategy"]
        steps = session["total_steps"]
        path = session["final_path"]

        cvss_scores = [s["chosen_score"] for s in session["steps"]]
        avg_score = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

        unique_targets = len(set(path))
        total_rejected = sum(len(s["rejected"]) for s in session["steps"])

        print(f"{strategy:<15}{steps:<8}{avg_score:<10.2f}{unique_targets:<16}{total_rejected}")


def diff_paths(sessions):
    print("\nPath overlap:")
    paths = {s["strategy"]: set(s["final_path"]) for s in sessions}
    names = list(paths.keys())

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            overlap = paths[a] & paths[b]
            print(f"  {a} vs {b}: {len(overlap)} shared nodes -> {sorted(overlap)}")


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    sessions = []
    for strategy in ["highest_cvss", "lowest_cvss", "random"]:
        session = simulate_with_full_log(G, strategy)
        sessions.append(session)

    compare_sessions(sessions)
    diff_paths(sessions)
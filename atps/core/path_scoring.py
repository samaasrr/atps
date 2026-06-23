import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from path_finder import find_all_paths_bfs, get_machine_only_paths


def score_path(G, path):
    cvss_scores = []
    privilege_levels = {"none": 0, "low": 1, "high": 2}
    privilege_gain = 0
    detection_risk = 0

    for node in path:
        data = G.nodes[node]
        if data.get("type") == "Machine":
            cvss = data.get("cvss", 0)
            cvss_scores.append(cvss)

            priv = data.get("privilege_impact", "none")
            privilege_gain += privilege_levels.get(priv, 0)

            if cvss >= 7.0:
                detection_risk += 2
            elif cvss >= 4.0:
                detection_risk += 1

    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
    score = avg_cvss + privilege_gain - detection_risk

    return {
        "path": path,
        "avg_cvss": round(avg_cvss, 2),
        "privilege_gain": privilege_gain,
        "detection_risk": detection_risk,
        "score": round(score, 2),
    }


def score_all_paths(G, paths):
    scored = [score_path(G, p) for p in paths]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def print_top_paths(scored_paths, top_n=10):
    print(f"\nTop {top_n} paths by score:")
    print(f"{'Score':<8}{'CVSS':<8}{'PrivGain':<10}{'Detect':<8}Path")
    print("-" * 70)
    for p in scored_paths[:top_n]:
        path_str = " -> ".join(p["path"])
        print(f"{p['score']:<8}{p['avg_cvss']:<8}{p['privilege_gain']:<10}{p['detection_risk']:<8}{path_str}")


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    bfs_paths = find_all_paths_bfs(G, max_depth=6)
    machine_paths = get_machine_only_paths(G, bfs_paths)

    scored = score_all_paths(G, machine_paths)
    print_top_paths(scored, top_n=10)
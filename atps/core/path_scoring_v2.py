import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from path_finder import find_all_paths_bfs, get_machine_only_paths


HIGH_VALUE_ROLES = ["domain_controller", "database"]

PRIVILEGE_WEIGHT = {"none": 0, "low": 1.5, "high": 3.0}


def score_path_v2(G, path):
    cvss_scores = []
    privilege_gain = 0
    detection_risk = 0
    asset_criticality = 0
    path_length = len(path) - 1

    for node in path:
        data = G.nodes[node]
        if data.get("type") != "Machine":
            continue

        cvss = data.get("cvss", 0)
        cvss_scores.append(cvss)

        priv = data.get("privilege_impact", "none")
        privilege_gain += PRIVILEGE_WEIGHT.get(priv, 0)

        if cvss >= 7.0:
            detection_risk += 2
        elif cvss >= 4.0:
            detection_risk += 1

        if data.get("role") in HIGH_VALUE_ROLES:
            asset_criticality += 3

    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
    length_penalty = path_length * 0.2

    score = avg_cvss + privilege_gain + asset_criticality - detection_risk - length_penalty

    return {
        "path": path,
        "avg_cvss": round(avg_cvss, 2),
        "privilege_gain": round(privilege_gain, 2),
        "asset_criticality": asset_criticality,
        "detection_risk": detection_risk,
        "length_penalty": round(length_penalty, 2),
        "score": round(score, 2),
    }


def score_all_v2(G, paths):
    scored = [score_path_v2(G, p) for p in paths]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def print_top_paths_v2(scored, top_n=10):
    print(f"\nTop {top_n} paths (v2 scoring):")
    print(f"{'Score':<8}{'CVSS':<8}{'Priv':<7}{'Crit':<6}{'Detect':<8}{'LenPen':<8}Path")
    print("-" * 80)
    for p in scored[:top_n]:
        path_str = " -> ".join(p["path"])
        print(f"{p['score']:<8}{p['avg_cvss']:<8}{p['privilege_gain']:<7}{p['asset_criticality']:<6}{p['detection_risk']:<8}{p['length_penalty']:<8}{path_str}")


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    paths = find_all_paths_bfs(G, max_depth=6)
    machine_paths = get_machine_only_paths(G, paths)

    scored = score_all_v2(G, machine_paths)
    print_top_paths_v2(scored, top_n=10)
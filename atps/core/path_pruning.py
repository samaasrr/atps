import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities
from path_finder import find_all_paths_bfs, get_machine_only_paths


def prune_by_max_depth(paths, max_depth=5):
    """
    Drop any path longer than max_depth hops.
    Prevents path explosion on large/dense graphs.
    """
    return [p for p in paths if (len(p) - 1) <= max_depth]


def prune_low_value_paths(G, paths, min_cvss=5.0):
    """
    Drop paths where every machine hop has CVSS below min_cvss.
    These paths are low-risk and clutter the results.
    """
    kept = []
    for path in paths:
        cvss_scores = [
            G.nodes[n].get("cvss", 0)
            for n in path
            if G.nodes[n].get("type") == "Machine"
        ]
        if cvss_scores and max(cvss_scores) >= min_cvss:
            kept.append(path)
    return kept


def deduplicate_paths(paths):
    """
    Remove exact duplicate paths (shouldn't happen with BFS + cycle
    prevention, but safety net for when we combine BFS/DFS results).
    """
    seen = set()
    unique = []
    for path in paths:
        key = tuple(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def cap_paths_per_target(paths, max_per_target=5):
    """
    Limit how many paths we keep per destination node.
    Prevents one heavily-connected machine from dominating the report.
    Keeps the shortest paths first (most realistic/likely).
    """
    by_target = {}
    for path in paths:
        target = path[-1]
        by_target.setdefault(target, []).append(path)

    capped = []
    for target, target_paths in by_target.items():
        target_paths.sort(key=len)  # shortest first
        capped.extend(target_paths[:max_per_target])

    return capped


def full_pruning_pipeline(G, paths, max_depth=5, min_cvss=5.0, max_per_target=5):
    """
    Run the full pruning pipeline in order:
    1. dedupe
    2. depth limit
    3. low-value filter
    4. cap per target
    """
    print(f"\n[pruning] starting with {len(paths)} paths")

    paths = deduplicate_paths(paths)
    print(f"[pruning] after dedup: {len(paths)}")

    paths = prune_by_max_depth(paths, max_depth=max_depth)
    print(f"[pruning] after max_depth={max_depth}: {len(paths)}")

    paths = prune_low_value_paths(G, paths, min_cvss=min_cvss)
    print(f"[pruning] after min_cvss={min_cvss}: {len(paths)}")

    paths = cap_paths_per_target(paths, max_per_target=max_per_target)
    print(f"[pruning] after cap_per_target={max_per_target}: {len(paths)}")

    return paths


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    bfs_paths = find_all_paths_bfs(G, max_depth=6)
    machine_paths = get_machine_only_paths(G, bfs_paths)

    print(f"\n[before pruning] {len(machine_paths)} machine-only paths")

    pruned = full_pruning_pipeline(G, machine_paths, max_depth=5, min_cvss=5.0, max_per_target=3)

    print(f"\n[after pruning] {len(pruned)} high-value paths remain")
    print("\nSample pruned paths:")
    for p in pruned[:10]:
        print(f"  {' → '.join(p)}")
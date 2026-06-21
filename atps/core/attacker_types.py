import sys
import os
import random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_generator import generate_network
from vulnerability_engine import assign_vulnerabilities


class Attacker:
    def __init__(self, G):
        self.G = G

    def get_neighbors(self, current, visited):
        return [n for n in self.G.successors(current) if n not in visited]

    def choose_next_step(self, current, visited):
        raise NotImplementedError


class GreedyAttacker(Attacker):
    name = "greedy"

    def choose_next_step(self, current, visited):
        neighbors = self.get_neighbors(current, visited)
        if not neighbors:
            return None
        machines = [n for n in neighbors if self.G.nodes[n].get("type") == "Machine"]
        if machines:
            return max(machines, key=lambda n: self.G.nodes[n].get("cvss", 0))
        return random.choice(neighbors)


class StealthAttacker(Attacker):
    name = "stealth"

    def choose_next_step(self, current, visited):
        neighbors = self.get_neighbors(current, visited)
        if not neighbors:
            return None
        machines = [n for n in neighbors if self.G.nodes[n].get("type") == "Machine"]
        scored = [n for n in machines if self.G.nodes[n].get("cvss", 0) > 0]
        if scored:
            return min(scored, key=lambda n: self.G.nodes[n].get("cvss", 0))
        return random.choice(neighbors)


class RandomAttacker(Attacker):
    name = "random"

    def choose_next_step(self, current, visited):
        neighbors = self.get_neighbors(current, visited)
        return random.choice(neighbors) if neighbors else None


def run_attacker(G, attacker, start="ATTACKER", max_steps=6):
    current = start
    path = [current]
    visited = {current}

    for _ in range(max_steps):
        next_node = attacker.choose_next_step(current, visited)
        if next_node is None:
            break
        path.append(next_node)
        visited.add(next_node)
        current = next_node

    return path


if __name__ == "__main__":
    G = generate_network(n_machines=10, n_users=5, seed=42)
    G = assign_vulnerabilities(G, seed=42)

    for AttackerClass in [GreedyAttacker, StealthAttacker, RandomAttacker]:
        attacker = AttackerClass(G)
        path = run_attacker(G, attacker)
        cvss = [G.nodes[n].get("cvss") for n in path if G.nodes[n].get("type") == "Machine"]
        cvss = [c for c in cvss if c is not None]
        print(f"{attacker.name}: {' -> '.join(path)}")
        if cvss:
            print(f"  avg cvss: {sum(cvss)/len(cvss):.1f}")
"""Central scanner orchestration utilities for SwanVA."""


class VAManager:
    """
    Central manager responsible for coordinating vulnerability scans.
    """

    def __init__(self):
        self.scanners = {}

    def register_scanner(self, name, scanner):
        self.scanners[name] = scanner

    def run_scanner(self, name, target):
        if name not in self.scanners:
            raise ValueError(f"Scanner {name} not registered")
        return self.scanners[name].run(target)

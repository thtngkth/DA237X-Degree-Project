"""
Compares Cargo metadata JSON with an SBOM, reporting on missing packages,
hallucinated packages, version mismatches, false dependencies,
and transitive dependency coverage.
"""

from collections import defaultdict
from cargo import CargoLock
from sbom import SBOM


class Comparator:
    """Compare Cargo metadata JSON with SBOM, including transitive coverage and version mismatches."""

    def __init__(self, cargo: CargoLock, sbom: SBOM):
        self.cargo = cargo
        self.sbom = sbom

    def calculate_transitive(self, adj, start):
        """
        Walk the dependency graph from 'start' and return all reachable nodes and their depths.
        Uses an explicit stack instead of recursion to avoid hitting Python's recursion limit.
        """
        visited = set()
        # Each entry in the stack is a (package_id, depth) pair
        nodes_to_visit = [(start, 0)]
        depths = {}

        while len(nodes_to_visit) > 0:
            node, depth = nodes_to_visit.pop()

            # Skip nodes we've already visited
            if node in visited:
                continue

            visited.add(node)
            depths[node] = depth

            # Add all neighbors to the stack with increased depth
            for neighbor in adj.get(node, []):
                nodes_to_visit.append((neighbor, depth + 1))

        # Remove the starting node itself — we only want its dependencies
        visited.discard(start)
        depths.pop(start, None)
        return visited, depths

    def compare(self):
        """Run all comparisons between the Cargo and SBOM data and store the results."""
        cargo_components = self.cargo.component_set()
        sbom_components = self.sbom.component_set()

        self.total_cargo_packages = len(self.cargo.packages)
        self.total_sbom_components = len(self.sbom.packages)

        # Find components present in Cargo but missing from the SBOM
        self.missed_components = set()
        for component in cargo_components:
            if component not in sbom_components:
                self.missed_components.add(component)

        # Find components in the SBOM that don't exist in Cargo (hallucinated)
        self.hallucinated_components = set()
        for component in sbom_components:
            if component not in cargo_components:
                self.hallucinated_components.add(component)

        # Calculate percentages, avoiding division by zero
        if len(cargo_components) > 0:
            self.missed_components_per = len(self.missed_components) / len(cargo_components) * 100
        else:
            self.missed_components_per = 0

        if len(sbom_components) > 0:
            self.hallucinated_components_per = len(self.hallucinated_components) / len(sbom_components) * 100
        else:
            self.hallucinated_components_per = 0

        cargo_edges = self.cargo.edges()
        sbom_edges = self.sbom.edges()

        # Find edges that are correct (present in both), missing, or false
        correct_edges = set()
        for edge in cargo_edges:
            if edge in sbom_edges:
                correct_edges.add(edge)

        self.missing_edges = set()
        for edge in cargo_edges:
            if edge not in sbom_edges:
                self.missing_edges.add(edge)

        self.false_edges = set()
        for edge in sbom_edges:
            if edge not in cargo_edges:
                self.false_edges.add(edge)

        # Calculate edge coverage percentages
        if len(cargo_edges) > 0:
            self.coverage = len(correct_edges) / len(cargo_edges) * 100
            self.missing_edges_per = len(self.missing_edges) / len(cargo_edges) * 100
        else:
            self.coverage = 0
            self.missing_edges_per = 0

        if len(sbom_edges) > 0:
            self.false_edges_per = len(self.false_edges) / len(sbom_edges) * 100
        else:
            self.false_edges_per = 0

        # Check for version mismatches between SBOM packages and Cargo packages
        lookup = self.cargo.build_lookup()
        self.version_mismatches = []
        self.missing_in_cargo = []

        for pkg in self.sbom.packages:
            if pkg.name in lookup:
                # Package exists in Cargo, but the version is different
                if pkg.version not in lookup[pkg.name]:
                    self.version_mismatches.append(pkg.id())
            else:
                # Package doesn't exist in Cargo at all
                self.missing_in_cargo.append(pkg.id())

        if self.total_sbom_components > 0:
            self.version_mismatch_per = len(self.version_mismatches) / self.total_sbom_components * 100
        else:
            self.version_mismatch_per = 0

        # Calculate transitive dependency coverage per package
        cargo_adj = self.cargo.adjacency()
        sbom_adj = self.sbom.adjacency()

        self.transitive_missing_hist = defaultdict(list)
        self.transitive_extra_hist = defaultdict(list)
        self.transitive_totals = {}
        self.depth_stats = []

        for pkg in cargo_adj.keys():
            cargo_set, cargo_depths = self.calculate_transitive(cargo_adj, pkg)
            sbom_set, sbom_depths = self.calculate_transitive(sbom_adj, pkg)

            # Find transitive deps that are missing from or extra in the SBOM
            missing = set()
            for dep in cargo_set:
                if dep not in sbom_set:
                    missing.add(dep)

            extra = set()
            for dep in sbom_set:
                if dep not in cargo_set:
                    extra.add(dep)

            self.transitive_missing_hist[len(missing)].append(pkg)
            self.transitive_extra_hist[len(extra)].append(pkg)
            self.transitive_totals[pkg] = len(cargo_set)

            # Record max depth reached in both graphs
            if len(cargo_depths) > 0:
                max_cargo_depth = max(cargo_depths.values())
                if len(sbom_depths) > 0:
                    max_sbom_depth = max(sbom_depths.values())
                else:
                    max_sbom_depth = 0
                self.depth_stats.append((pkg, max_cargo_depth, max_sbom_depth))

    def write_report(self, path):
        """Write all comparison results to a text report file."""
        with open(path, "w") as f:
            f.write("===== TOTAL COMPONENTS =====\n")
            f.write(f"Total Cargo packages: {self.total_cargo_packages}\n")
            f.write(f"Total SBOM components: {self.total_sbom_components}\n\n")

            f.write("===== EDGE METRICS =====\n")
            f.write(f"Correct edge coverage: {self.coverage:.2f}%\n")
            f.write(f"Missing edges: {len(self.missing_edges)} ({self.missing_edges_per:.2f}%)\n")
            f.write(f"False edges: {len(self.false_edges)} ({self.false_edges_per:.2f}%)\n\n")

            if len(self.false_edges) > 0:
                f.write("===== FALSE EDGES =====\n")
                for pkg_name, pkg_version, dep_name, dep_version in sorted(self.false_edges):
                    f.write(f"{pkg_name} ({pkg_version}) -> {dep_name} ({dep_version})\n")
                f.write("\n")
            f.write("===== COMPONENT METRICS =====\n")
            f.write(f"Missed components: {len(self.missed_components)} ({self.missed_components_per:.2f}%)\n")
            f.write(f"Hallucinated components: {len(self.hallucinated_components)} ({self.hallucinated_components_per:.2f}%)\n\n")

            f.write("===== VERSION MISMATCHES =====\n")
            f.write(f"Version mismatches: {len(self.version_mismatches)} ({self.version_mismatch_per:.2f}%)\n\n")

            f.write("===== TRANSITIVE DEPENDENCY =====\n")
            coverage_counts = defaultdict(int)
            full_coverage_count = 0
            total_packages = len(self.transitive_totals)

            for pkg, total in self.transitive_totals.items():
                # Look up how many transitive deps are missing for this package
                missing_count = 0
                for count, packages in self.transitive_missing_hist.items():
                    if pkg in packages:
                        missing_count = count
                        break

                # Calculate coverage percentage for this package
                if total > 0:
                    coverage = (total - missing_count) / total * 100
                else:
                    coverage = 100

                coverage_rounded = round(coverage)
                coverage_counts[coverage_rounded] += 1

                if coverage_rounded == 100:
                    full_coverage_count += 1

            f.write("Distribution of packages by coverage (%):\n")
            for cov in sorted(coverage_counts.keys(), reverse=True):
                count = coverage_counts[cov]
                f.write(f"{cov}% coverage: {count} package(s) ({count / total_packages * 100:.2f}%)\n")

            f.write("\n===== END OF REPORT =====\n")
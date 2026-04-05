"""
Program to compare Cargo.lock dependencies with SBOM (CycloneDX JSON) components.
It identifies missing packages, hallucinated packages, version mismatches, false dependencies
and transitive dependency coverage.
"""

import tomllib
import json
from urllib.parse import unquote
from collections import defaultdict


class Package:
    """Represents a single package/component with name, version, source, and dependencies."""

    def __init__(self, name, version, source, dependencies):
        self.name = name.lower().strip()
        self.version = version
        self.source = source
        self.dependencies = dependencies  # list of tuples: (name, version)

    def id(self):
        """Return a unique identifier for the package (name, version)."""
        return (self.name, self.version)


# ----------------- CARGO ----------------- #

class CargoLock:
    """Parses Cargo.lock and provides dependency graphs and lookups."""

    def __init__(self, path):
        self.packages = []
        self.read(path)

    def read(self, path):
        """Read Cargo.lock and extract packages and their dependencies."""

        with open(path, "rb") as f:
            data = tomllib.load(f)

        for pkg in data.get("package", []):
            deps = []
            for dep in pkg.get("dependencies", []):
                parts = dep.split()
                dep_name = parts[0].lower().strip()
                dep_version = parts[1] if len(parts) > 1 else None
                deps.append((dep_name, dep_version))

            self.packages.append(
                Package(pkg.get("name"), pkg.get("version"), pkg.get("source"), deps)
            )

    def build_lookup(self):
        """Build a lookup dictionary: name -> version -> source."""

        lookup = {}
        for p in self.packages:
            lookup.setdefault(p.name, {})[p.version] = p.source
        return lookup

    def edges(self):
        """Return set of direct dependency edges as tuples: (pkg_name, pkg_version, dep_name, dep_version)."""

        edges = set()
        lookup = self.build_lookup()

        for pkg in self.packages:
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    # Resolve missing version by checking available versions
                    for v in lookup.get(dep_name, {}).keys():
                        edges.add((pkg.name, pkg.version, dep_name, v))
                else:
                    edges.add((pkg.name, pkg.version, dep_name, dep_version))
        return edges

    def build_resolver(self):
        """Return a mapping from (name, source) -> version for resolving dependencies."""

        resolver = {}
        for p in self.packages:
            resolver[(p.name, p.source)] = p.version
        return resolver

    def component_set(self):
        """Return a set of (name, version) for all packages."""

        return {p.id() for p in self.packages}

    def adjacency(self):
        """Return a dictionary of transitive dependencies: pkg_id -> list of neighbor pkg_ids."""

        adj = {}
        resolver = self.build_resolver()

        for pkg in self.packages:
            neighbors = []
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    
                    resolved_version = resolver.get((dep_name, pkg.source))
                    if resolved_version:
                        neighbors.append((dep_name, resolved_version))
                else:
                    neighbors.append((dep_name, dep_version))
            adj[pkg.id()] = neighbors
        return adj


# ----------------- SBOM ----------------- #

class SBOM:
    """Parses CycloneDX SBOM (JSON) and provides dependency graphs and lookups."""

    def __init__(self, path):
        self.packages = []
        self.read(path)

    def parse_purl(self, purl):
        """Parse a purl string to extract package name and version (Cargo only)."""

        
        purl = unquote(purl).split("?")[0].replace("pkg:cargo/", "")
        if "@" not in purl:
            return purl.lower().strip(), None
        name, version = purl.split("@", 1)
        return name.lower().strip(), version

    def extract_sbom_url(self, component):
        """Return the distribution URL for a component if available."""

        for url in component.get("externalReferences", []):
            if url.get("type") == "distribution":
                return url.get("url")
        return "unknown"

    def create_dependency_map(self, sbom):
        """Create a mapping from component bom-ref to its dependencies."""

        dep_map = {}
        for d in sbom.get("dependencies", []):
            ref = d.get("ref") or d.get("bom-ref")
            if ref:
                dep_map[ref] = d.get("dependsOn", [])
        return dep_map

    def read(self, path):
        """Parse SBOM JSON, filter Cargo packages, and build package objects."""

        with open(path) as f:
            sbom = json.load(f)

        # Map bom-ref -> purl for dependency resolution
        ref_to_purl = {
            c.get("bom-ref"): c.get("purl")
            for c in sbom.get("components", [])
            if c.get("bom-ref")
        }

        dep_map = self.create_dependency_map(sbom)

        for comp in sbom.get("components", []):
            purl = comp.get("purl")
            if not purl or not purl.startswith("pkg:cargo/"):
                continue

            name, version = self.parse_purl(purl)

            deps = []
            for ref in dep_map.get(comp.get("bom-ref"), []):
                dep_purl = ref_to_purl.get(ref)
                if not dep_purl:
                    continue
                dep_name, dep_version = self.parse_purl(dep_purl)
                deps.append((dep_name, dep_version))

            source = self.extract_sbom_url(comp)
            self.packages.append(Package(name, version, source, deps))

    def edges(self):
        """Return set of direct dependency edges: (pkg_name, pkg_version, dep_name, dep_version)."""

        edges = set()
        for pkg in self.packages:
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    continue
                edges.add((pkg.name, pkg.version, dep_name, dep_version))
        return edges

    def component_set(self):
        """Return set of all components (name, version)."""

        return {p.id() for p in self.packages}

    def adjacency(self):
        """Return adjacency mapping for transitive dependencies."""

        adj = {}
        name_index = defaultdict(list)
        for p in self.packages:
            name_index[p.name].append(p.version)

        for pkg in self.packages:
            neighbors = []
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    # Resolve to all known versions in SBOM
                    for v in name_index.get(dep_name, []):
                        neighbors.append((dep_name, v))
                else:
                    neighbors.append((dep_name, dep_version))
            adj[pkg.id()] = neighbors
        return adj


# ----------------- COMPARATOR ----------------- #

class Comparator:
    """Compare Cargo.lock with SBOM, including transitive coverage and version mismatches."""

    def __init__(self, cargo: CargoLock, sbom: SBOM):
        self.cargo = cargo
        self.sbom = sbom

    def calculate_transitive(self, adj, start):
        """Compute transitive dependencies and their depths using DFS."""

        visited = set()
        stack = [(start, 0)]
        depths = {}

        while stack:
            node, depth = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            depths[node] = depth
            for neighbor in adj.get(node, []):
                stack.append((neighbor, depth + 1))

        visited.discard(start)
        depths.pop(start, None)
        return visited, depths

    def compare(self):
        """Perform full comparison between Cargo.lock and SBOM."""

        cargo_components = self.cargo.component_set()
        sbom_components = self.sbom.component_set()

        # Package-level metrics
        self.total_cargo_packages = len(self.cargo.packages)
        self.total_sbom_components = len(self.sbom.packages)
        self.missed_components = cargo_components - sbom_components
        self.hallucinated_components = sbom_components - cargo_components
        self.missed_components_per = (
            len(self.missed_components) / len(cargo_components) * 100 if cargo_components else 0
        )
        self.hallucinated_components_per = (
            len(self.hallucinated_components) / len(sbom_components) * 100 if sbom_components else 0
        )

        # Edge-level metrics (direct dependencies)
        cargo_edges = self.cargo.edges()
        sbom_edges = self.sbom.edges()
        correct = cargo_edges & sbom_edges
        self.missing_edges = cargo_edges - sbom_edges
        self.false_edges = sbom_edges - cargo_edges
        self.coverage = (len(correct) / len(cargo_edges) * 100) if cargo_edges else 0
        self.missing_edges_per = (len(self.missing_edges) / len(cargo_edges) * 100) if cargo_edges else 0
        self.false_edges_per = (len(self.false_edges) / len(sbom_edges) * 100) if sbom_edges else 0

        # Version mismatches
        lookup = self.cargo.build_lookup()
        self.version_mismatches = []
        self.missing_in_cargo = []

        for pkg in self.sbom.packages:
            if pkg.name in lookup:
                if pkg.version not in lookup[pkg.name]:
                    self.version_mismatches.append(pkg.id())
            else:
                self.missing_in_cargo.append(pkg.id())

        self.version_mismatch_per = (
            len(self.version_mismatches) / self.total_sbom_components * 100
            if self.total_sbom_components else 0
        )

        # Transitive dependencies
        cargo_adj = self.cargo.adjacency()
        sbom_adj = self.sbom.adjacency()

        self.transitive_missing_hist = defaultdict(list)
        self.transitive_extra_hist = defaultdict(list)
        self.transitive_totals = {}
        self.depth_stats = []

        for pkg in cargo_adj.keys():
            cargo_set, cargo_depths = self.calculate_transitive(cargo_adj, pkg)
            sbom_set, sbom_depths = self.calculate_transitive(sbom_adj, pkg)

            missing = cargo_set - sbom_set
            extra = sbom_set - cargo_set

            self.transitive_missing_hist[len(missing)].append(pkg)
            self.transitive_extra_hist[len(extra)].append(pkg)
            self.transitive_totals[pkg] = len(cargo_set)

            if cargo_depths:
                max_cargo_depth = max(cargo_depths.values())
                max_sbom_depth = max(sbom_depths.values()) if sbom_depths else 0
                self.depth_stats.append((pkg, max_cargo_depth, max_sbom_depth))

    def print_transitive_chains(self, adj, start, max_depth=15):
        """Print all transitive dependency chains from a start package."""

        stack = [(start, [start])]
        while stack:
            node, path = stack.pop()
            if len(path) > max_depth:
                continue
            neighbors = adj.get(node, [])
            if not neighbors:
                chain = " -> ".join([f"{n[0]}@{n[1]}" for n in path])
                print(chain)
                continue
            for neighbor in neighbors:
                if neighbor in path:
                    continue
                stack.append((neighbor, path + [neighbor]))

    def write_report(self, path):
        """Write a summary report to a text file, including transitive coverage statistics."""
        with open(path, "w") as f:
            # --- Basic metrics ---
            f.write("===== TOTAL COMPONENTS =====\n")
            f.write(f"Total Cargo packages: {self.total_cargo_packages}\n")
            f.write(f"Total SBOM components: {self.total_sbom_components}\n\n")

            f.write("===== EDGE METRICS =====\n")
            f.write(f"Correct edge coverage: {self.coverage:.2f}%\n")
            f.write(f"Missing edges: {len(self.missing_edges)} ({self.missing_edges_per:.2f}%)\n")
            f.write(f"False edges: {len(self.false_edges)} ({self.false_edges_per:.2f}%)\n\n")

            f.write("===== COMPONENT METRICS =====\n")
            f.write(f"Missed components: {len(self.missed_components)} ({self.missed_components_per:.2f}%)\n")
            f.write(f"Hallucinated components: {len(self.hallucinated_components)} ({self.hallucinated_components_per:.2f}%)\n\n")

            f.write("===== VERSION MISMATCHES =====\n")
            f.write(f"Version mismatches: {len(self.version_mismatches)} ({self.version_mismatch_per:.2f}%)\n\n")

            # --- Per package transitive coverage ---
            f.write("===== PER PACKAGE TRANSITIVE COVERAGE =====\n")

            coverage_counts = defaultdict(int)
            full_coverage_count = 0
            total_packages = len(self.transitive_totals)

            for pkg, total in self.transitive_totals.items():
                missing = None
                for k, v in self.transitive_missing_hist.items():
                    if pkg in v:
                        missing = k
                        break
                if total > 0:
                    coverage = (total - missing) / total * 100
                else:
                    coverage = 100  # no dependencies means trivially 100%
                
                coverage_rounded = round(coverage)
                coverage_counts[coverage_rounded] += 1
                if coverage_rounded == 100:
                    full_coverage_count += 1

                f.write(f"{pkg[0]}@{pkg[1]}: {coverage:.2f}% coverage\n")

            # --- Transitive coverage summary ---
            f.write("\n===== TRANSITIVE COVERAGE SUMMARY =====\n")
            f.write(f"Packages with 100% transitive coverage: {full_coverage_count} "
                    f"({full_coverage_count / total_packages * 100:.2f}%)\n\n")
            f.write("Distribution of packages by coverage (%):\n")
            for cov in sorted(coverage_counts.keys(), reverse=True):
                count = coverage_counts[cov]
                f.write(f"{cov}% coverage: {count} package(s) "
                        f"({count / total_packages * 100:.2f}%)\n")


def main():
    cargo_path = "/mnt/c/Users/vntra/Downloads/rustdesk/Cargo.lock"
    sbom_path = "/mnt/c/Users/vntra/Downloads/rustdesk/syft-cyclonedx.json"

    cargo = CargoLock(cargo_path)
    sbom = SBOM(sbom_path)

    comp = Comparator(cargo, sbom)
    comp.compare()
    comp.write_report("hej.txt")


if __name__ == "__main__":
    main()
"""
Compares Cargo metadata JSON with an SBOM, reporting on missing packages,
version mismatches, false dependencies, and transitive dependency coverage.
"""

import os
from collections import defaultdict
from openpyxl import load_workbook
from openpyxl import Workbook
from openpyxl.styles import Font
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

        # Name-only lookup
        cargo_names = {pkg.name for pkg in self.cargo.packages}
        sbom_names = {pkg.name for pkg in self.sbom.packages}

        lookup = self.cargo.build_lookup()

        # Missed components
        self.missed_components = set()
        for (name, version) in cargo_components:
            if name not in sbom_names:
                self.missed_components.add((name, version))

        # Invented packages
        seen_invented = set()
        self.missing_in_cargo = []
        for pkg in self.sbom.packages:
            if pkg.name not in cargo_names:
                if pkg.name not in seen_invented:     # only count each name once
                    seen_invented.add(pkg.name)
                    self.missing_in_cargo.append(pkg.id())

        # Version mismatches (SBOM-side)
        seen_mismatches = set()
        self.version_mismatches = []
        for pkg in self.sbom.packages:
            if pkg.name in lookup:
                if pkg.version not in lookup[pkg.name]:
                    key = pkg.id()                    # (name, version) tuple
                    if key not in seen_mismatches:    # only count each (name, version) once
                        seen_mismatches.add(key)
                        self.version_mismatches.append(key)

        if self.total_sbom_components > 0:
            self.version_mismatches_per = (len(self.version_mismatches) / self.total_sbom_components * 100)
        else:
            self.version_mismatches_per = 0

        # Version mismatches (Cargo-side)
        self.cargo_version_mismatched = set()
        for (name, version) in cargo_components:
            if name in sbom_names:
                if (name, version) not in sbom_components:
                    self.cargo_version_mismatched.add((name, version))

        self.correctly_identified = cargo_components & sbom_components

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

        # Calculate the average transitive coverage score across all packages
        coverage_scores = []
        for pkg, total in self.transitive_totals.items():
            # Find how many transitive deps are missing for this package
            missing_count = 0
            for count, packages in self.transitive_missing_hist.items():
                if pkg in packages:
                    missing_count = count
                    break

            if total > 0:
                score = (total - missing_count) / total * 100
            else:
                # A package with no transitive deps is trivially fully covered
                score = 100

            coverage_scores.append(score)

        if len(coverage_scores) > 0:
            self.avg_transitive_coverage = sum(coverage_scores) / len(coverage_scores)
        else:
            self.avg_transitive_coverage = 0

    @staticmethod
    def clear_report(path):
        """
        Clear all data rows from the Excel file.
        """
        wb = load_workbook(path)
        sheet = wb.active

        # Delete every row from row 2 downward
        if sheet.max_row >= 2:
            sheet.delete_rows(2, sheet.max_row - 1)

        wb.save(path)
        print(f"Cleared existing data from {path}")

    def write_report(self, path, sbom_path):
        """Append one formatted row of results to the Excel file."""
        # Create Excel file if it doesn't exist
        if not os.path.exists(path):
            wb = Workbook()
            sheet = wb.active
            sheet.append([
                "Project",
                "Cargo pkg",
                "SBOM pkg",
                "Correctly identified pkg",
                "Cargo version mismatched",
                "Edg coverage (%)",
                "Edg missing",
                "False edg",
                "Missed comp",
                "Invented pkg",
                "Version mismatch",
                "Avg trans dep (%)",
                "100% trans dep",
                "0% trans dep",
            ])
            wb.save(path)

        wb = load_workbook(path)
        sheet = wb.active

        # Percentage count
        def percentage_count(count, total):
            if total == 0:
                return "0% (0)"
            pct = (count / total) * 100
            return f"{pct:.2f}% ({count})"

        # Transitive coverage 
        count_100 = 0
        count_0 = 0

        for pkg, total in self.transitive_totals.items():
            missing_count = 0
            for count, packages in self.transitive_missing_hist.items():
                if pkg in packages:
                    missing_count = count
                    break

            coverage = (total - missing_count) / total * 100 if total > 0 else 100
            rounded = round(coverage)

            if rounded == 100:
                count_100 += 1
            elif rounded == 0:
                count_0 += 1

        total_pkgs = len(self.transitive_totals)

        # Project name from SBOM path 
        project_name = os.path.splitext(os.path.basename(sbom_path))[0]

        # Build formatted row 
        new_row = [
            project_name,
            self.total_cargo_packages,
            self.total_sbom_components,
            len(self.correctly_identified),
            len(self.cargo_version_mismatched),
            f"{self.coverage:.2f}",

            percentage_count(len(self.missing_edges), len(self.cargo.edges())),
            percentage_count(len(self.false_edges), len(self.sbom.edges())),
            percentage_count(len(self.missed_components), len(self.cargo.component_set())),
            percentage_count(len(self.missing_in_cargo), self.total_sbom_components),
            percentage_count(len(self.version_mismatches), self.total_sbom_components),

            f"{self.avg_transitive_coverage:.2f}",

            percentage_count(count_100, total_pkgs),
            percentage_count(count_0, total_pkgs),
        ]

        last_data_row = 0
        for row in sheet.iter_rows(values_only=True):
            if any(cell is not None for cell in row):
                last_data_row +=1

        for col_index, value in enumerate(new_row, start = 1):
            sheet.cell(row = last_data_row + 1, column = col_index, value = value)

        # ---- Style row ----
        last_row = sheet.max_row
        for col in range(1, len(new_row) + 1):
            sheet.cell(row=last_row, column=col).font = Font(name="Arial")

        wb.save(path)
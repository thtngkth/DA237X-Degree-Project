import tomllib
import json
from urllib.parse import unquote


# ----------------- MODEL -----------------

class Package:
    def __init__(self, name, version, source, dependencies):
        self.name = name.lower().strip()
        self.version = version
        self.source = source
        self.dependencies = dependencies  # list of (name, version)

    def id(self):
        return (self.name, self.version)


# ----------------- CARGO -----------------

class CargoLock:
    def __init__(self, path):
        self.packages = []
        self.read(path)

    def read(self, path):
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
                Package(
                    pkg.get("name"),
                    pkg.get("version"),
                    pkg.get("source"),
                    deps,
                )
            )

    def build_lookup(self):
        lookup = {}
        for p in self.packages:
            lookup.setdefault(p.name, {})[p.version] = p.source
        return lookup

    def edges(self):
        edges = set()
        lookup = self.build_lookup()

        for pkg in self.packages:
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    # resolve missing version
                    for v in lookup.get(dep_name, {}).keys():
                        edges.add((pkg.name, pkg.version, dep_name, v))
                else:
                    edges.add((pkg.name, pkg.version, dep_name, dep_version))

        return edges

    def component_set(self):
        return {p.id() for p in self.packages}


# ----------------- SBOM -----------------

class SBOM:
    def __init__(self, path):
        self.packages = []
        self.read(path)

    def parse_purl(self, purl):
        purl = unquote(purl)
        purl = purl.split("?")[0]
        purl = purl.replace("pkg:cargo/", "")

        if "@" not in purl:
            return purl.lower().strip(), None

        name, version = purl.split("@", 1)
        return name.lower().strip(), version

    def extract_sbom_url(self, component):
        for url in component.get("externalReferences", []):
            if url.get("type") == "distribution":
                return url.get("url")
        return "unknown"

    def read(self, path):
        with open(path) as f:
            sbom = json.load(f)

        # Build bom-ref -> purl map (CRITICAL FIX)
        ref_to_purl = {
            c.get("bom-ref"): c.get("purl")
            for c in sbom.get("components", [])
            if c.get("bom-ref")
        }

        # Defensive dependency map (CRITICAL FIX)
        dep_map = {}
        for d in sbom.get("dependencies", []):
            ref = d.get("ref") or d.get("bom-ref")
            if ref:
                dep_map[ref] = d.get("dependsOn", [])

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

            self.packages.append(
                Package(name, version, source, deps)
            )

    def edges(self):
        edges = set()
        for pkg in self.packages:
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    continue
                edges.add((pkg.name, pkg.version, dep_name, dep_version))
        return edges

    def component_set(self):
        return {p.id() for p in self.packages}


# ----------------- COMPARATOR -----------------

class Comparator:
    def __init__(self, cargo, sbom):
        self.cargo = cargo
        self.sbom = sbom

    def compare(self):
        cargo_components = self.cargo.component_set()
        sbom_components = self.sbom.component_set()

        self.total_cargo_packages = len(self.cargo.packages)
        self.total_sbom_components = len(self.sbom.packages)

        self.missed_components = cargo_components - sbom_components
        self.hallucinated_components = sbom_components - cargo_components

        self.missed_components_pct = (
            len(self.missed_components) / len(cargo_components) * 100
            if cargo_components else 0
        )
        self.hallucinated_components_pct = (
            len(self.hallucinated_components) / len(sbom_components) * 100
            if sbom_components else 0
        )

        cargo_edges = self.cargo.edges()
        sbom_edges = self.sbom.edges()

        correct = cargo_edges & sbom_edges
        self.missing_edges = cargo_edges - sbom_edges
        self.false_edges = sbom_edges - cargo_edges

        self.coverage = (len(correct) / len(cargo_edges) * 100) if cargo_edges else 0
        self.missing_edges_pct = (len(self.missing_edges) / len(cargo_edges) * 100) if cargo_edges else 0
        self.false_edges_pct = (len(self.false_edges) / len(sbom_edges) * 100) if sbom_edges else 0

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

        self.version_mismatch_pct = (
            len(self.version_mismatches) / self.total_sbom_components * 100
            if self.total_sbom_components else 0
        )
    
    def write_report(self, path):
        with open(path, "w") as f:
            f.write("===== TOTAL COMPONENTS =====\n")
            f.write(f"Total Cargo packages: {self.total_cargo_packages}\n")
            f.write(f"Total SBOM components: {self.total_sbom_components}\n\n")

            f.write("===== EDGE METRICS =====\n")
            f.write(f"Correct edge coverage: {self.coverage:.2f}%\n")
            f.write(f"Missing edges: {len(self.missing_edges)} ({self.missing_edges_pct:.2f}%)\n")
            f.write(f"False edges: {len(self.false_edges)} ({self.false_edges_pct:.2f}%)\n\n")

            f.write("===== COMPONENT METRICS =====\n")
            f.write(f"Missed components: {len(self.missed_components)} ({self.missed_components_pct:.2f}%)\n")
            f.write(f"Hallucinated components: {len(self.hallucinated_components)} ({self.hallucinated_components_pct:.2f}%)\n\n")

            f.write("===== VERSION MISMATCHES =====\n")
            f.write(f"Version mismatches: {len(self.version_mismatches)} ({self.version_mismatch_pct:.2f}%)\n")

# ----------------- MAIN -----------------

def main():
    cargo_path = "/mnt/c/Users/vntra/Downloads/rustdesk/Cargo.lock"
    sbom_path = "/mnt/c/Users/vntra/Downloads/rustdesk/syft-cyclonedx.json"

    cargo = CargoLock(cargo_path)
    sbom = SBOM(sbom_path)

    comp = Comparator(cargo, sbom)
    comp.compare()
    comp.write_report("results_new.txt")


if __name__ == "__main__":
    main()
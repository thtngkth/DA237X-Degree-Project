"""
Parses CycloneDX SBOM (JSON) and provides dependency graphs and lookups.
"""

import json
from urllib.parse import unquote
from package import Package


class SBOM:
    """Parses CycloneDX SBOM (JSON) and provides dependency graphs and lookups."""

    def __init__(self, path):
        self.packages = []
        self.read(path)

    def parse_purl(self, purl):
        """Parse a purl string to extract package name and version (Cargo only)."""
        # Decode URL encoding, remove query string, and strip the 'pkg:cargo/' prefix
        purl = unquote(purl)
        purl = purl.split("?")[0]
        purl = purl.replace("pkg:cargo/", "")

        # If there's no '@', there's no version
        if "@" not in purl:
            return purl.lower().strip(), None

        # Split into name and version at the first '@'
        name, version = purl.split("@", 1)
        return name.lower().strip(), version

    def extract_sbom_url(self, component):
        """Return the distribution URL for a component if available."""
        for url in component.get("externalReferences", []):
            if url.get("type") == "distribution":
                return url.get("url")
        return "unknown"

    def create_dependency_map(self, sbom):
        """Create a mapping from component bom-ref to its list of dependency refs."""
        dep_map = {}
        for d in sbom.get("dependencies", []):
            # Some SBOMs use 'ref', others use 'bom-ref'
            ref = d.get("ref")
            if ref is None:
                ref = d.get("bom-ref")
            if ref is not None:
                dep_map[ref] = d.get("dependsOn", [])
        return dep_map

    def read(self, path):
        """Parse SBOM JSON, filter Cargo packages, and build package objects."""
        with open(path) as f:
            sbom = json.load(f)

        # Build a map from bom-ref -> purl for all components
        ref_to_purl = {}
        for c in sbom.get("components", []):
            bom_ref = c.get("bom-ref")
            if bom_ref is not None:
                ref_to_purl[bom_ref] = c.get("purl")

        dep_map = self.create_dependency_map(sbom)

        for comp in sbom.get("components", []):
            purl = comp.get("purl")

            # Skip components that aren't Cargo packages
            if purl is None or not purl.startswith("pkg:cargo/"):
                continue

            name, version = self.parse_purl(purl)

            # Build list of dependencies using bom-ref lookups
            deps = []
            bom_ref = comp.get("bom-ref")
            for ref in dep_map.get(bom_ref, []):
                dep_purl = ref_to_purl.get(ref)
                if dep_purl is None:
                    continue
                dep_name, dep_version = self.parse_purl(dep_purl)
                deps.append((dep_name, dep_version))

            source = self.extract_sbom_url(comp)
            self.packages.append(Package(name, version, source, deps))

    def edges(self):
        """Return set of direct dependency edges as tuples: (pkg_name, pkg_version, dep_name, dep_version)."""
        edges = set()
        for pkg in self.packages:
            for dep_name, dep_version in pkg.dependencies:
                # Skip dependencies where the version is unknown
                if dep_version is None:
                    continue
                edges.add((pkg.name, pkg.version, dep_name, dep_version))
        return edges

    def component_set(self):
        """Return a set of (name, version) tuples for all packages."""
        all_ids = set()
        for p in self.packages:
            all_ids.add(p.id())
        return all_ids

    def adjacency(self):
        """Return a dictionary mapping each package id to its list of direct dependency ids."""
        adj = {}

        # Build a name -> list of versions index for resolving unknown versions
        name_index = {}
        for p in self.packages:
            if p.name not in name_index:
                name_index[p.name] = []
            name_index[p.name].append(p.version)

        for pkg in self.packages:
            neighbors = []
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    # Add all known versions of this dependency
                    for v in name_index.get(dep_name, []):
                        neighbors.append((dep_name, v))
                else:
                    neighbors.append((dep_name, dep_version))
            adj[pkg.id()] = neighbors

        return adj
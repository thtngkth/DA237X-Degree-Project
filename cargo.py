"""
Parses Cargo metadata JSON and provides dependency graphs and lookups.
"""

import json
from package import Package


def parse_version(version_str):
    """
    Parse a version string like '1.2.3' into a tuple of integers (1, 2, 3).
    Returns None if the string can't be parsed.
    """
    # Strip any pre-release or build metadata suffix (e.g. "1.2.3-alpha" -> "1.2.3")
    version_str = version_str.strip().split("-")[0].split("+")[0]

    parts = version_str.split(".")
    result = []
    for part in parts:
        if part.isdigit():
            result.append(int(part))
        else:
            break

    if len(result) == 0:
        return None

    # Pad to at least 3 components: (major, minor, patch)
    while len(result) < 3:
        result.append(0)

    return tuple(result)


def check_single_clause(clause, installed_version_str):
    """
    Check whether an installed version satisfies a single requirement clause
    (i.e. one without any commas).

    Supported formats:
      - "1.2.3"    : semver-compatible with 1.2.3 (same as ^1.2.3)
      - "^1.2.3"   : semver-compatible (major must match if major > 0)
      - "~1.2.3"   : compatible, but only the patch component can increase
      - "=1.2.3"   : exact match only
      - ">=1.2.3"  : greater than or equal
      - "<=1.2.3"  : less than or equal
      - ">1.2.3"   : strictly greater than
      - "<1.2.3"   : strictly less than
      - "*"        : any version is acceptable
    """
    clause = clause.strip()

    if clause == "*":
        return True

    # Detect the operator prefix (check >= and <= before = > <)
    if clause.startswith(">="):
        operator = ">="
        version_part = clause[2:].strip()
    elif clause.startswith("<="):
        operator = "<="
        version_part = clause[2:].strip()
    elif clause.startswith("="):
        operator = "="
        version_part = clause[1:].strip()
    elif clause.startswith("^"):
        operator = "^"
        version_part = clause[1:].strip()
    elif clause.startswith("~"):
        operator = "~"
        version_part = clause[1:].strip()
    elif clause.startswith(">"):
        operator = ">"
        version_part = clause[1:].strip()
    elif clause.startswith("<"):
        operator = "<"
        version_part = clause[1:].strip()
    else:
        # No operator means "^" (semver-compatible) by default
        operator = "^"
        version_part = clause

    req_ver = parse_version(version_part)
    ins_ver = parse_version(installed_version_str)

    if req_ver is None or ins_ver is None:
        return False

    req_major, req_minor, req_patch = req_ver
    ins_major, ins_minor, ins_patch = ins_ver

    if operator == "=":
        return ins_ver == req_ver

    elif operator == "^":
        # Semver-compatible: installed must be >= req, and within the same major version.
        # Special case: if major is 0, the minor is the "breaking" component.
        # Special case: if major and minor are both 0, patch is the "breaking" component.
        if ins_ver < req_ver:
            return False
        if req_major != 0:
            return ins_major == req_major
        elif req_minor != 0:
            return ins_major == 0 and ins_minor == req_minor
        else:
            return ins_major == 0 and ins_minor == 0 and ins_patch == req_patch

    elif operator == "~":
        # Tilde: installed must be >= req, and major + minor must match exactly
        if ins_ver < req_ver:
            return False
        return ins_major == req_major and ins_minor == req_minor

    elif operator == ">=":
        return ins_ver >= req_ver

    elif operator == "<=":
        return ins_ver <= req_ver

    elif operator == ">":
        return ins_ver > req_ver

    elif operator == "<":
        return ins_ver < req_ver

    return False


def version_satisfies_req(req_str, installed_version_str):
    """
    Check whether an installed version satisfies a full Cargo version requirement string.
    """
    # Get individual clauses, e.g. [">=0.52", "<0.62"]
    clauses = req_str.split(",")

    # Every clause must be satisfied (AND logic)
    for clause in clauses:
        if not check_single_clause(clause.strip(), installed_version_str):
            return False

    return True


class CargoLock:
    """Parses Cargo metadata JSON and provides dependency graphs and lookups."""

    def __init__(self, path):
        self.packages = []
        self.read(path)

    def read(self, path):
        """Read Cargo metadata JSON and extract packages and dependencies."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # First pass: build a name -> list of (version, source) lookup.
        # A package name can have multiple installed versions, so we store a list.
        name_to_versions = {}
        for pkg in data.get("packages", []):
            name = pkg["name"].lower().strip()
            version = pkg["version"]
            source = pkg.get("source", "local")

            if name not in name_to_versions:
                name_to_versions[name] = []
            name_to_versions[name].append((version, source))

        # Second pass: build Package objects with semver-resolved dependencies
        for pkg in data.get("packages", []):
            name = pkg["name"].lower().strip()
            version = pkg["version"]
            source = pkg.get("source", "local")

            dependencies = []
            for dep in pkg.get("dependencies", []):
                dep_name = dep["name"].lower().strip()
                dep_req = dep.get("req", "*")

                # Find ALL installed versions that satisfy the version requirement.
                for installed_version, installed_source in name_to_versions.get(dep_name, []):
                    if version_satisfies_req(dep_req, installed_version):
                        dependencies.append((dep_name, installed_version))

            self.packages.append(Package(name, version, source, dependencies))

    def build_lookup(self):
        """Build a lookup dictionary: name -> version -> source."""
        lookup = {}
        for p in self.packages:
            if p.name not in lookup:
                lookup[p.name] = {}
            lookup[p.name][p.version] = p.source
        return lookup

    def edges(self):
        """Return set of direct dependency edges as tuples: (pkg_name, pkg_version, dep_name, dep_version)."""
        edges = set()
        lookup = self.build_lookup()

        for pkg in self.packages:
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    # Version is unknown, so add an edge for every known version of this dep
                    known_versions = lookup.get(dep_name, {}).keys()
                    for v in known_versions:
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
        """Return a set of (name, version) tuples for all packages."""
        all_ids = set()
        for p in self.packages:
            all_ids.add(p.id())
        return all_ids

    def adjacency(self):
        """Return a dictionary mapping each package id to its list of direct dependency ids."""
        adj = {}
        resolver = self.build_resolver()

        for pkg in self.packages:
            neighbors = []
            for dep_name, dep_version in pkg.dependencies:
                if dep_version is None:
                    resolved_version = resolver.get((dep_name, pkg.source))
                    if resolved_version is not None:
                        neighbors.append((dep_name, resolved_version))
                else:
                    neighbors.append((dep_name, dep_version))
            adj[pkg.id()] = neighbors

        return adj
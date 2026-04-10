"""
Represents a single software package with its name, version, source, and dependencies.
"""

class Package:
    """Represents a single package/component with name, version, source, and dependencies."""
 
    def __init__(self, name, version, source, dependencies):
        self.name = name.lower().strip()
        self.version = version
        self.source = source
        self.dependencies = dependencies  # list of tuples: (name, version)
 
    def id(self):
        """Return a unique identifier for the package as a (name, version) tuple."""
        return (self.name, self.version)
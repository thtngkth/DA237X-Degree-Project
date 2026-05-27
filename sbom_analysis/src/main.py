"""
Main entry point for the Cargo vs SBOM comparison tool.
"""

from pathlib import Path
from cargo import CargoLock
from sbom import SBOM
from comparator import Comparator
from collections import defaultdict

ROOT = Path(__file__).parent.parent
BASE_PATH = "/mnt/c/Users/vntra/Downloads/rust_projects"

def detect_tool(sbom_filename: str):
    """Detects the SBOM tool by SBOM file"""
    name = sbom_filename.lower()

    if name.endswith(".cdx.json"):
        return "cyclonedx"
    if name == "syft.json":
        return "syft"
    if name == "trivy.json":
        return "trivy"
    if name == "cargosbom.json":
        return "cargosbom"

    return None

def read_files(path):
    """Read path.txt and return a list of (cargo_path, sbom_path) pairs."""
    pairs = []
 
    with open(path) as f:
        for line in f:
            line = line.strip()
 
            if line == "" or line.startswith("#"):
                continue
 
            parts = line.split("|")

            if len(parts) != 2:
                print(f"Warning, malformed line in path.txt: '{line}' - skipping")
                continue
 
            project_name = parts[0].strip()
            sbom_rel = parts[1].strip()
 
            cargo_path = f"{BASE_PATH}/{project_name}/metadata.json"
            sbom_path  = f"{BASE_PATH}/{sbom_rel}"
 
            pairs.append((project_name, cargo_path, sbom_path))
 
    return pairs
 
def get_sbom_files(sbom_path):
    """
    Return all SBOM files inside the folder.
    """
    path_obj = Path(sbom_path)
 
    if path_obj.is_dir():
        # Find all JSON files in the folder
        sbom_files = list(path_obj.glob("*.json"))
 
        if len(sbom_files) == 0:
            print(f"  Warning: no JSON files found in folder {sbom_path}")
 
        return sbom_files
    else:
        return [path_obj]
 
def main():
    path_file = ROOT / "path.txt"
 
    file_pairs = read_files(path_file)

    output_files = {
        "cyclonedx": ROOT / "cdx.xlsx",
        "syft": ROOT / "syft.xlsx",
        "trivy": ROOT / "trivy.xlsx",
        "cargosbom": ROOT / "cargosbom.xlsx",
    }

    for output_file in output_files.values():
        # Clear the Excel file before starting the comparisons
        Comparator.clear_report(output_file)
    
    tool_results = defaultdict(list)
    run_number = 1

    for project_name, cargo_path, sbom_path in file_pairs:
        # Get the list of SBOM files to process
        sbom_files = get_sbom_files(sbom_path)

        for sbom_file in sbom_files:
            tool = detect_tool(sbom_file.name)

            if tool is None:
                print(f"Warning, couldn't detect tool for '{sbom_file.name}' - skipping")
                continue

            output_file = output_files[tool]

            print("\n=== Running comparison", run_number, "===")
            print(f"Project: {project_name}")
            print(f"Tool   : {tool}")
            print("Cargo:", cargo_path)
            print("SBOM :", sbom_file)
            print(f"Output : {output_file}")
 
            # Load and parse both files
            cargo = CargoLock(cargo_path)
            sbom = SBOM(sbom_file)
 
            # Run the comparison
            comp = Comparator(cargo, sbom)
            comp.compare()

            comp.write_report(output_file, project_name)
            print("Report written to", output_file)
 
            run_number += 1
 
if __name__ == "__main__":
    main()
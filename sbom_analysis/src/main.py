"""
Main entry point for the Cargo vs SBOM comparison tool.
"""

from pathlib import Path
from cargo import CargoLock
from sbom import SBOM
from comparator import Comparator

ROOT = Path(__file__).parent.parent
BASE_PATH = "/rust_projects"

def read_files(path):
    """Read path.txt and return a list of (cargo_path, sbom_path) pairs."""
    pairs = []
 
    with open(path) as f:
        for line in f:
            line = line.strip()
 
            if line == "" or line.startswith("#"):
                continue
 
            parts = line.split("|")
 
            cargo_rel = parts[0].strip()
            sbom_rel = parts[1].strip()
 
            cargo_path = f"{BASE_PATH}/{cargo_rel}/metadata.json"
            sbom_path  = f"{BASE_PATH}/{sbom_rel}"
 
            pairs.append((cargo_path, sbom_path))
 
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
 
    run_number = 1

    # Clear the Excel file before starting the comparisons
    output_file = ROOT / "sbom_results.xlsx"
    Comparator.clear_report(output_file)
 
    for pair in file_pairs:
        cargo_path = pair[0]
        sbom_path_or_folder = pair[1]
 
        # Get the list of SBOM files to process
        sbom_files = get_sbom_files(sbom_path_or_folder)
 
        for sbom_file in sbom_files:
            print("\n=== Running comparison", run_number, "===")
            print("Cargo:", cargo_path)
            print("SBOM :", sbom_file)
 
            # Load and parse both files
            cargo = CargoLock(cargo_path)
            sbom = SBOM(sbom_file)
 
            # Run the comparison
            comp = Comparator(cargo, sbom)
            comp.compare()
 
            output_file = "sbom_results.xlsx"
 
            comp.write_report(output_file, sbom_file)
            print("Report written to", output_file)
 
            run_number += 1
 
if __name__ == "__main__":
    main()
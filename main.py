"""
Main entry point for the Cargo vs SBOM comparison tool.
"""

from pathlib import Path
from cargo import CargoLock
from sbom import SBOM
from comparator import Comparator

def read_files(path):
    """Read path.txt and return a list of (cargo_path, sbom_path)."""
    pairs = []

    with open(path) as f:
        for line in f:
            line = line.strip()

            if line == "" or line.startswith("#"):
                continue

            parts = line.split("|")

            cargo_path = parts[0].strip()
            sbom_path = parts[1].strip()

            pairs.append((cargo_path, sbom_path))

    return pairs


def main():
    path_file = "path.txt"

    file_pairs = read_files(path_file)

    run_number = 1

    # Create folder to save the reports
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    for pair in file_pairs:
        cargo_path = pair[0]
        sbom_path = pair[1]

        print("\n=== Running comparison", run_number, "===")
        print("Cargo:", cargo_path)
        print("SBOM :", sbom_path)

        cargo = CargoLock(cargo_path)
        sbom = SBOM(sbom_path)

        comp = Comparator(cargo, sbom)
        comp.compare()

        # Extract repo name
        sbom_path_obj = Path(sbom_path)

        try:
            rust_index = sbom_path_obj.parts.index("rust_projects")
            repo_name = sbom_path_obj.parts[rust_index + 1]
        except (ValueError, IndexError):
            repo_name = sbom_path_obj.stem  # fallback if 'rust_projects' not in path

        # Name report after SBOM file
        sbom_name = sbom_path_obj.stem
        output_file = reports_dir / f"{repo_name}_{sbom_name}_report.txt"

        comp.write_report(output_file)
        print("Report written to", output_file)

        run_number += 1

if __name__ == "__main__":
    main()
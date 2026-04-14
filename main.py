"""
Main entry point for the Cargo vs SBOM comparison tool.
"""

from pathlib import Path
from cargo import CargoLock
from sbom import SBOM
from comparator import Comparator


def read_files(path):
    """Read path.txt and return a list of (cargo_path, sbom_path) pairs."""
    pairs = []

    with open(path) as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comment lines
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

    for pair in file_pairs:
        cargo_path = pair[0]
        sbom_path = pair[1]

        print("\n=== Running comparison", run_number, "===")
        print("Cargo:", cargo_path)
        print("SBOM :", sbom_path)

        # Load and parse both files
        cargo = CargoLock(cargo_path)
        sbom = SBOM(sbom_path)

        # Run the comparison
        comp = Comparator(cargo, sbom)
        comp.compare()

        # Always write to the shared sbom_results.xlsx file
        output_file = "real_sbom_results.xlsx"

        comp.write_report(output_file, sbom_path)
        print("Report written to", output_file)

        run_number += 1


# Only run main() when this file is executed directly, not when imported
if __name__ == "__main__":
    main()
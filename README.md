# SBOM

## Purpose
This program compares the `Cargo.lock` dependencies of a Rust project with the components listed in a `SBOM `(Software Bill of Materials) in CycloneDX format. It provides a detailed comparison of package names, versions, sources, and dependency graphs.

- Total number of Cargo.lock packages
- Total number of SBOM components
- Missed components (exist in Cargo.lock but not in SBOM)
- Correct edges (dependencies correctly represented in the SBOM)
- Missing edges (dependencies in Cargo.lock not represented in the SBOM)
- False edges (dependencies in SBOM not present in Cargo.lock)
- Version mismatches (packages with the same name but different versions)
- Hallucinated components (exist in SBOM but not in Cargo.lock)

`Cargo.lock` is treated as the ground truth.

## Requirements
`SBOM` in CycloneDX JSON format

## Usage
1. Edit the paths in `main()`
2. Run `python3 sbom_comparator.py`

The program generates a `results.txt` file. 
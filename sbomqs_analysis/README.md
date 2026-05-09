# SBOM Quality Scoring Tool

A tool for running [sbomqs](https://github.com/interlynk-io/sbomqs) quality checks across multiple Rust projects and writing the results to an Excel report. It evaluates each SBOM file against both a basic score and the BSI TR-03183-2 v2.1 profile.

---

## What it Does

For each project listed in `path.txt`, the tool:

1. Runs `sbomqs score --basic --recursive` on the project's `sbom/` folder — scoring all SBOM files
2. Runs `sbomqs score --profile bsi-v2.1` on each individual SBOM file
3. Writes all results to `sbomqs_results.xlsx`

The following SBOM files are recognised per project:

| Filename | Tool |
|---|---|
| `syft.json` | Syft |
| `trivy.json` | Trivy |
| `cargosbom.json` | Cargo SBOM |
| `*.cdx.json` | CycloneDX Rust Cargo |

---

## Project Structure

```
sbomqs_analysis/
├── path.txt               # List of SBOM folders to process
├── sbomqs_results.xlsx    # Generated output (must exist before first run)
├── run_sbomqs.sh          # Bash script that runs sbomqs and calls the parser
└── parse_sbomqs.py        # Python script that parses output and writes to Excel
```

---

## Requirements

### System dependencies

- [`sbomqs`](https://github.com/interlynk-io/sbomqs) — must be installed and available on `PATH`
- Python 3.8 or later
- Bash

### Python dependencies

```bash
pip install openpyxl
```

---

## Configuration

### 1. Set the base path

Open both `run_sbomqs.sh` and `parse_sbomqs.py` and set `BASE_PATH` to the folder containing all your Rust projects:

**In `run_sbomqs.sh`:**
```bash
BASE_PATH="<path>"
```

**In `parse_sbomqs.py`:**
```python
BASE_PATH = "<path>"
```

### 2. Edit `path.txt`

Each line specifies the path to one project's SBOM folder, relative to `BASE_PATH`. Lines starting with `#` and empty lines are ignored.

```
# path.txt
# Format: <relative path to sbom folder>

# Top projects
atuin/sbom
firecracker/sbom
gitbutler/sbom
meilisearch/sbom
```

This resolves to full paths like:
```
"<path>"atuin/sbom
"<path>"firecracker/sbom
```

### 3. Prepare the Excel file

The Excel file (`sbomqs_results.xlsx`) must exist before running the script — the tool writes into an existing file rather than creating one from scratch. The file must have two header rows set up with tool names in row 1 and sub-headers in row 2. Data is written from row 3 onwards.

---

## Usage

Make the script executable (first time only):

```bash
chmod +x run_sbomqs.sh
```

Then run it:

```bash
./run_sbomqs.sh
```

---

## Output

Results are written to `sbomqs_results.xlsx`. Each row represents one project and includes the following columns per tool:

| Column | Description |
|---|---|
| `sbomqs score` | Basic quality score from `sbomqs score --basic` |
| `bsi-v2.1` | Overall BSI score and grade, e.g. `7.5/10.0 (B)` |
| `required` | Required fields compliance, e.g. `12/13` |
| `additional` | Additional fields compliance, e.g. `3/5` |
| `optional` | Optional fields present, e.g. `2/4` |

---
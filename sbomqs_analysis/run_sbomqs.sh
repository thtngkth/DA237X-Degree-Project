#!/usr/bin/env bash
# run_sbomqs.sh
# Runs sbomqs on each project folder and writes the results to Excel.
# Reads project folder paths from path.txt (one path per line).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATHS_FILE="$SCRIPT_DIR/path.txt"
EXCEL_FILE="$SCRIPT_DIR/sbomqs_results.xlsx"
PYTHON_SCRIPT="$SCRIPT_DIR/parse_sbomqs.py"

BASE_PATH="/rust_projects"

# Check that path.txt exists
if [[ ! -f "$PATHS_FILE" ]]; then
    echo "[ERROR] path.txt not found at: $PATHS_FILE"
    exit 1
fi

# Temporary files to collect sbomqs output before writing to Excel
TMP_BASIC="$(mktemp)"
TMP_BSI="$(mktemp)"

# Loop over each path in path.txt
while IFS= read -r entry || [[ -n "$entry" ]]; do

    # Skip comments and empty lines
    [[ "$entry" =~ ^#.*$ || -z "$entry" ]] && continue

    entry="$(echo "$entry" | tr -d '\r' | sed 's/[[:space:]]*$//')"

    # If the path is already absolute
    if [[ "$entry" == /* ]]; then
        dir="$entry"
    else
        dir="$BASE_PATH/$entry"
    fi

    if [[ ! -d "$dir" ]]; then
        echo "[SKIP] Folder not found: $dir"
        continue
    fi

    # Extract the project name
    project="$(echo "$dir" | grep -oP '(?<=rust_projects/)[^/]+')"
    echo "Processing: $project ($dir)"

    # Basic score for all SBOM files
    basic_output=$(sbomqs score --basic --recursive "$dir" 2>&1)
    echo "PROJECT=$project"  >> "$TMP_BASIC"
    echo "$basic_output"     >> "$TMP_BASIC"
    echo "---END---"         >> "$TMP_BASIC"

    # BSI v2.1 score for fixed-name SBOM files
    for tool in trivy syft cargosbom; do
        file="$dir/$tool.json"
        if [[ -f "$file" ]]; then
            echo "  BSI score: $tool"
            bsi_output=$(sbomqs score --profile bsi-v2.1 "$file" 2>&1)
            echo "PROJECT=$project" >> "$TMP_BSI"
            echo "TOOL=$tool"       >> "$TMP_BSI"
            echo "$bsi_output"      >> "$TMP_BSI"
            echo "---END---"        >> "$TMP_BSI"
        fi
    done

    # BSI v2.1 score for *.cdx.json files
    for cdx_file in "$dir"/*.cdx.json; do
        if [[ -f "$cdx_file" ]]; then
            echo "  BSI score: cyclonedx ($(basename "$cdx_file"))"
            bsi_output=$(sbomqs score --profile bsi-v2.1 "$cdx_file" 2>&1)
            echo "PROJECT=$project"  >> "$TMP_BSI"
            echo "TOOL=cyclonedx"    >> "$TMP_BSI"
            echo "$bsi_output"       >> "$TMP_BSI"
            echo "---END---"         >> "$TMP_BSI"
        fi
    done

    echo ""

done < "$PATHS_FILE"

# Write everything to Excel
echo "Writing results to $EXCEL_FILE ..."
python3 "$PYTHON_SCRIPT" "$TMP_BASIC" "$TMP_BSI" "$EXCEL_FILE"

# Clean up temporary files
rm -f "$TMP_BASIC" "$TMP_BSI"
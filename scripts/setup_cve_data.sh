#!/bin/bash
# Setup script for CVE data repository

set -e

echo "=========================================="
echo "CVEMaps - CVE Data Setup"
echo "=========================================="
echo ""

# Get the repository root directory (parent of scripts/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Default to cve-data in repo root, but allow override
CVE_DATA_DIR=${CVE_DATA_DIR:-"$REPO_ROOT/cve-data"}

echo "Repository root: $REPO_ROOT"
echo "CVE data target: $CVE_DATA_DIR"
echo ""

if [ -d "$CVE_DATA_DIR" ]; then
    echo "✓ CVE data directory already exists at: $CVE_DATA_DIR"
    echo ""
    echo "Updating CVE data..."
    cd "$CVE_DATA_DIR"
    git pull
    cd "$REPO_ROOT"
    echo "✓ CVE data updated"
else
    echo "Cloning CVE data repository..."
    echo "This is a large repository (~10GB), please be patient..."
    echo ""
    
    cd "$REPO_ROOT"
    git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve-data
    
    echo ""
    echo "✓ CVE data cloned successfully to: $CVE_DATA_DIR"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "CVE data is located at:"
echo "  $CVE_DATA_DIR"
echo ""
echo "You can now run (from repository root):"
echo "  python scripts/build_graph.py               # Build main graphs"
echo "  python scripts/build_alternative_graphs.py  # Build alternative visualizations"
echo "  python scripts/build_compact_graphs.py      # Build compact layouts"
echo "  python scripts/build_extended_graphs.py     # Build extended visualizations"
echo ""

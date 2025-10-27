# Scripts Directory

This directory contains all build and setup scripts for CVEMaps.

## Build Scripts

### `build_graph.py`
**Main graph generation script**

Builds the primary CNA-to-CWE association graph:
- Parses CVE JSON files from the CVEListV5 repository
- Extracts CNA (CVE Numbering Authority) and CWE (Common Weakness Enumeration) relationships
- Generates NetworkX graph with weighted edges
- Outputs: `web/data/cna_to_cwe_map.json`

**Usage:**
```bash
python scripts/build_graph.py
```

### `build_alternative_graphs.py`
**Alternative visualization builder**

Creates additional graph visualizations:
- **CWE Co-occurrence**: Shows which CWEs appear together in CVEs
- **Top 50 Bipartite**: Top CNAs and their associated CWEs in bipartite layout
- **CWE Hierarchy**: Tree structure of CWE relationships
- **CWE Star Graphs**: Star layouts for individual CWEs
- **Circular Layout**: Circular arrangement of CWE nodes
- **CNA Collaboration**: Network showing CNA relationships
- **MITRE Ego Network**: MITRE-centric view of connections

**Usage:**
```bash
python scripts/build_alternative_graphs.py
```

### `build_compact_graphs.py`
**Compact layout generator**

Generates space-efficient NetworkX layouts:
- Uses spring layout algorithm for compact arrangements
- Optimized for large graphs
- Reduces visual clutter

**Usage:**
```bash
python scripts/build_compact_graphs.py
```

### `build_extended_graphs.py`
**Extended visualizations with CVSS and vendor data**

Creates advanced visualizations including:
- **Vendor Vulnerability Profiles**: Top vendors and their CWE associations
- **CNA-Vendor Reporting Map**: Shows which CNAs report on which vendors
- **Sankey Flow Diagram**: Flow from CNAs to CWEs
- **Heatmap Matrix**: CNA vs CWE intensity matrix
- **CVSS Severity Distribution**: Distribution of vulnerability severities
- **Temporal Trends**: CVE publication trends over time

**Outputs:**
- `web/data/vendor_vulnerability_profiles.json`
- `web/data/cna_vendor_map.json`
- `web/data/sankey_flow.json`
- `web/data/heatmap_matrix.json`
- `web/data/cvss_severity_distribution.json`
- `web/data/temporal_trends.json`

**Usage:**
```bash
python scripts/build_extended_graphs.py
```

## Setup Scripts

### `setup_cve_data.sh`
**CVE data repository setup**

Automates the process of cloning and updating the CVE data repository:
- Clones CVEListV5 repository if not present
- Updates existing repository with latest CVE data
- Uses `--depth 1` for faster cloning

**Usage:**
```bash
chmod +x scripts/setup_cve_data.sh
./scripts/setup_cve_data.sh
```

**Environment Variables:**
- `CVE_DATA_DIR`: Override default CVE data location (default: `cve-data`)

## Configuration

All scripts use the configuration from `config.py` in the scripts directory:

```python
# Add scripts directory to path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import Config

config = Config.from_env()
# Access: config.CVE_DATA_DIR, config.WEB_DATA_DIR, config.DAYS_BACK
```

**Environment Variables:**
- `CVE_DATA_DIR`: Path to CVE data directory (default: `cve-data/cves`)
- `WEB_DATA_DIR`: Path to web data output (default: `web/data`)
- `DAYS_BACK`: Number of days of CVE data to process (default: 365)

## Running All Scripts

To build all visualizations at once:

```bash
# Setup CVE data first
./scripts/setup_cve_data.sh

# Build all graphs
python scripts/build_graph.py
python scripts/build_alternative_graphs.py
python scripts/build_compact_graphs.py
python scripts/build_extended_graphs.py
```

Or use the GitHub Actions workflow which runs all scripts automatically.

## Requirements

- Python 3.11+
- NetworkX 3.0+
- CVEListV5 repository cloned to `cve-data/`

Install dependencies:
```bash
pip install networkx
```

## Output Files

All scripts generate JSON files in `web/data/`:

| File | Created By | Description |
|------|------------|-------------|
| `cna_to_cwe_map.json` | `build_graph.py` | Main CNA-CWE graph |
| `cwe_cooccurrence_map.json` | `build_alternative_graphs.py` | CWE co-occurrence network |
| `top_cna_cwe_bipartite.json` | `build_alternative_graphs.py` | Top 50 bipartite layout |
| `cwe_hierarchy_tree.json` | `build_alternative_graphs.py` | CWE hierarchy tree |
| `cwe_star_graphs.json` | `build_alternative_graphs.py` | CWE star graphs |
| `cwe_circular_layout.json` | `build_alternative_graphs.py` | Circular CWE layout |
| `cna_collaboration.json` | `build_alternative_graphs.py` | CNA collaboration network |
| `mitre_ego_network.json` | `build_alternative_graphs.py` | MITRE ego network |
| `vendor_vulnerability_profiles.json` | `build_extended_graphs.py` | Vendor-CWE associations |
| `cna_vendor_map.json` | `build_extended_graphs.py` | CNA-vendor reporting map |
| `sankey_flow.json` | `build_extended_graphs.py` | Sankey flow diagram data |
| `heatmap_matrix.json` | `build_extended_graphs.py` | CNA-CWE heatmap matrix |
| `cvss_severity_distribution.json` | `build_extended_graphs.py` | CVSS severity stats |
| `temporal_trends.json` | `build_extended_graphs.py` | Time-based CVE trends |

## Development

To add a new visualization:

1. Create data extraction logic in appropriate build script
2. Export JSON to `web/data/`
3. Create HTML visualization in `web/`
4. Update `web/index.html` to link to new visualization
5. Update this README

## Troubleshooting

**Error: "CVE data directory not found"**
- Run `./scripts/setup_cve_data.sh` first
- Or set `CVE_DATA_DIR` environment variable

**Error: "No module named 'config'"**
- Ensure you're running scripts from the project root directory
- Or run directly from scripts directory: `cd scripts && python build_graph.py`

**Script runs but no output**
- Check that CVE data exists in `cve-data/cves/`
- Verify `web/data/` directory is writable
- Check for errors in console output

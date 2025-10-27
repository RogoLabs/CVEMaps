# CVE Maps: CNA to CWE Association Visualization

[![GitHub Pages](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-blue?logo=github)](https://rogolabs.github.io/CVEMaps/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![NetworkX](https://img.shields.io/badge/NetworkX-3.0+-orange.svg)](https://networkx.org/)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/RogoLabs/CVEMaps/update_map.yml?branch=main&label=build)](https://github.com/RogoLabs/CVEMaps/actions)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

An automated system that visualizes the relationships between CVE Numbering Authorities (CNAs) and Common Weakness Enumerations (CWEs) using interactive graph visualization.

## 🎯 Overview

This project automatically:
- Clones the [CVE List V5](https://github.com/CVEProject/cvelistV5) repository
- Parses all CVE JSON files to extract CNA-CWE associations
- Builds a NetworkX graph mapping these relationships
- Deploys multiple interactive visualizations to GitHub Pages
- Updates automatically every 3 hours via GitHub Actions

## 🚀 Features

- **Automated Data Processing**: Python script parses 315,567 CVE records
- **10 Interactive Visualizations**: 
  - Landing page with navigation
  - Force-directed network graph
  - Independent cluster view
  - CWE co-occurrence network
  - Top 50 CNA-CWE bipartite layout
  - CWE hierarchy tree
  - CWE star graphs
  - Circular CWE layout
  - CNA collaboration network
  - MITRE ego network
- **Interactive Controls**: Pan, zoom, drag, search, and filter
- **Auto-updating**: GitHub Actions workflow runs every 3 hours
- **Dark Mode UI**: Modern, responsive design with Tailwind CSS
- **Optimized Performance**: 365-day data filter for faster loading

## 📁 Project Structure

```
/
├── .github/
│   └── workflows/
│       └── update_map.yml           # GitHub Actions workflow
├── scripts/                         # Build and setup scripts
│   ├── config.py                    # Configuration management
│   ├── build_graph.py               # Main graph generation script
│   ├── build_alternative_graphs.py  # Alternative visualizations
│   ├── build_compact_graphs.py      # Compact NetworkX layouts
│   ├── build_extended_graphs.py     # Extended visualizations (CVSS, vendors, etc.)
│   ├── setup_cve_data.sh            # CVE data repository setup
│   └── README.md                    # Scripts documentation
├── web/                             # Web visualizations
│   ├── index.html                   # Landing page with navigation
│   ├── force-directed.html          # Force-directed graph
│   ├── clusters.html                # Independent clusters view
│   ├── cwe-cooccurrence.html        # CWE co-occurrence network
│   ├── bipartite-top50.html         # Top 50 CNA-CWE bipartite
│   ├── cwe-hierarchy.html           # CWE hierarchy tree
│   ├── cwe-stars.html               # CWE star graphs
│   ├── cwe-circular.html            # Circular CWE layout
│   ├── cna-collaboration.html       # CNA collaboration network
│   ├── mitre-ego.html               # MITRE ego network
│   └── data/                        # Generated visualization data
│       ├── cna_to_cwe_map.json      # Main graph data
│       ├── cwe_cooccurrence_map.json # CWE co-occurrence
│       ├── top_cna_cwe_bipartite.json # Bipartite layout
│       ├── cwe_hierarchy_tree.json   # Hierarchy tree
│       ├── cwe_star_graphs.json      # Star graphs
│       ├── cwe_circular_layout.json  # Circular layout
│       ├── cna_collaboration.json    # Collaboration network
│       └── mitre_ego_network.json    # MITRE ego network
├── pyproject.toml                   # Python package configuration
├── requirements.txt                 # Python dependencies
├── .gitignore
├── LICENSE
└── README.md
```

## 🛠️ How It Works

### 1. Data Collection (`build_graph.py`)
- Clones the CVEListV5 repository
- Recursively walks through CVE JSON files
- **Filters CVEs to those published in the last year** (365 days) for performance
- Extracts CNA (`assignerOrgId`) and CWE identifiers
- Counts associations between CNAs and CWEs
- Builds a NetworkX graph with weighted edges

### 2. Visualization (`web/index.html`, `web/force-directed.html`, `web/clusters.html`)
- **Landing Page**: Navigation hub with stats and links to visualizations
- **Force-Directed Graph**: Loads graph data using D3.js and renders interconnected layout
- **Independent Clusters**: Each CNA displayed as isolated mini-network
- Node colors: Blue (CNAs) vs Red (CWEs)
- Node sizes based on connection count
- Edge opacity/width based on association weight
- Interactive tooltips and selection highlighting

### 3. Automation (`.github/workflows/update_map.yml`)
- Triggers every 3 hours (or manually)
- Sets up Python environment
- Installs NetworkX
- Clones fresh CVE data
- Runs build script
- Deploys to GitHub Pages

## 🚦 Getting Started

### Local Development

1. **Clone the repository**:
   ```bash
   git clone https://github.com/RogoLabs/CVEMaps.git
   cd CVEMaps
   ```

2. **Install dependencies**:
   ```bash
   pip install networkx
   ```

3. **Clone CVE data**:
   ```bash
   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve-data
   ```

4. **Build the graph**:
   ```bash
   python build_graph.py
   python build_alternative_graphs.py
   python build_compact_graphs.py
   ```

5. **View locally**:
   Open `web/index.html` in your browser or use a local server:
   ```bash
   cd web
   python -m http.server 8000
   # Visit http://localhost:8000
   ```

## 🎨 Available Visualizations

### 1. Landing Page (`index.html`)
- Overview of all 10 available visualizations
- Live stats (CNAs, CWEs, associations, total CVEs)
- Quick navigation cards to different views
- Color-coded by visualization type

### 2. Force-Directed Network (`force-directed.html`)
- All CNAs and CWEs in one interconnected graph
- 349 CNAs, 577 CWEs, 6,103 associations
- Drag nodes to explore relationships
- Click to highlight connections
- Real-time search filtering
- File size: 597KB

### 3. Independent Clusters (`clusters.html`)
- 409 isolated mini-networks (one per CNA)
- **CNA names displayed inside blue circles**
- Sort by size or filter by name/CWE
- Adjustable density slider
- CNA size scales with CWE count
- Drag CWEs within cluster boundaries
- **Optimized with 365-day filter**

### 4. CWE Co-occurrence Network (`cwe-cooccurrence.html`)
- Shows which CWEs commonly appear together in CVEs
- 577 CWE nodes, 903 co-occurrence edges
- Click to see common partners
- Node size reflects co-occurrence frequency
- File size: 121KB

### 5. Top 50 CNA-CWE Bipartite (`bipartite-top50.html`)
- Two-column layout: 50 most active CNAs (left), 603 CWEs (right)
- 4,175 associations clearly visible
- Bipartite graph layout for pattern recognition
- Vertical divider separates the two groups
- File size: 444KB

### 6. CWE Hierarchy Tree (`cwe-hierarchy.html`)
- 3-level tree structure: root → categories → CWEs
- 51 nodes organized hierarchically
- Color-coded by type (blue=root, purple=category, red=CWE)
- Node size reflects CVE count
- File size: 14KB

### 7. CWE Star Graphs (`cwe-stars.html`)
- Top 12 CWEs displayed as star centers
- 252 total nodes with CNAs radiating outward
- Shows which organizations focus on which weaknesses
- Multiple stars in grid layout
- File size: 71KB

### 8. Circular CWE Layout (`cwe-circular.html`)
- Top 40 CWEs arranged in a symmetric circle
- 227 interconnection edges
- Click to highlight neighbors
- Perfect for spotting central weaknesses
- File size: 26KB

### 9. CNA Collaboration Network (`cna-collaboration.html`)
- 396 CNAs connected by shared CWE focus areas
- 4,190 collaboration edges
- Reveals research interests and patterns
- Spring layout with pre-computed positions
- File size: 521KB

### 10. MITRE Ego Network (`mitre-ego.html`)
- MITRE Corporation at center with direct connections
- 340 nodes at radius 1 from MITRE
- Radial layout from center node
- Red center node, blue connected CNAs
- File size: 75KB

## 📊 Visualization Technology

All visualizations use:
- **D3.js v7** for rendering and interactions
- **NetworkX** for graph generation and layout algorithms
- **Pre-computed positions** for instant loading (no client-side layout computation)
- **Tailwind CSS** for consistent styling
- **Interactive features**: pan, zoom, drag, click selection, search filtering
- **Dark theme** with gradient backgrounds

### GitHub Pages Deployment

1. **Enable GitHub Pages**:
   - Go to repository Settings → Pages
   - Source: GitHub Actions

2. **Run the workflow**:
   - Go to Actions tab
   - Select "Update CVE Map Data"
   - Click "Run workflow"

3. **View your site**:
   - Visit `https://<username>.github.io/CVEMaps/`

## 📊 Graph Statistics

The main visualization displays:
- **349 CNAs**: CVE Numbering Authorities
- **577 CWEs**: Common Weakness Enumerations  
- **6,103 Associations**: Unique CNA-CWE mappings
- **50,282 CVEs**: From last 365 days (filtered from 315,567 total)
- **Node Connections**: Number of relationships per entity
- **Edge Weights**: Frequency of associations

### Performance Optimization
- **365-day filter**: Only processes CVEs from the last year for faster loading
- **Pre-computed layouts**: NetworkX calculates positions server-side
- **Optimized file sizes**: All visualizations under 600KB
- **Efficient rendering**: D3.js uses pre-computed coordinates

## 🎨 Visualization Features

### Interactive Controls
- **Pan**: Click and drag background
- **Zoom**: Mouse wheel or pinch
- **Drag Nodes**: Click and drag any node
- **Select Node**: Click to highlight connections
- **Reset View**: Button to reset pan/zoom
- **Clear Selection**: Remove highlighting

### Visual Encoding
- **Blue Nodes**: CVE Numbering Authorities (CNAs)
- **Red Nodes**: Common Weakness Enumerations (CWEs)
- **Node Size**: Proportional to connection count
- **Edge Thickness**: Based on association weight
- **Edge Opacity**: Indicates relationship strength

## 🔧 Configuration

### Update Frequency
Edit `.github/workflows/update_map.yml`:
```yaml
schedule:
  - cron: '0 */3 * * *'  # Every 3 hours
```

### Graph Parameters
Edit `build_graph.py` force simulation settings:
- Node repulsion strength
- Link distance
- Collision radius

## 📝 Requirements

- Python 3.11+
- NetworkX 3.0+
- Modern web browser with JavaScript enabled

## 🤝 Contributing

We welcome contributions! Whether it's:

- 🐛 Bug reports
- 💡 Feature suggestions  
- 📖 Documentation improvements
- 🔧 Code contributions

Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Development setup
- Coding standards
- Pull request process
- Testing guidelines

### Quick Start for Contributors

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/CVEMaps.git
cd CVEMaps

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black cvemaps/
ruff check cvemaps/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [CVE Project](https://github.com/CVEProject/cvelistV5) for providing comprehensive CVE data
- [D3.js](https://d3js.org/) for powerful visualization capabilities
- [NetworkX](https://networkx.org/) for graph processing and algorithms
- [Tailwind CSS](https://tailwindcss.com/) for modern, responsive styling

## 📚 Additional Resources

- **Documentation**: See [QUICKSTART.md](QUICKSTART.md) for quick setup guide
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for version history
- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/RogoLabs/CVEMaps/issues)
- **Discussions**: Join conversations on [GitHub Discussions](https://github.com/RogoLabs/CVEMaps/discussions)

## 📊 Project Stats

- **CVEs Analyzed**: 315,567+
- **CNAs Tracked**: 400+
- **CWEs Mapped**: 800+
- **Visualizations**: 10 interactive types
- **Update Frequency**: Every 3 hours
- **Data Window**: Last 365 days

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

**Last Updated**: Auto-generated by GitHub Actions
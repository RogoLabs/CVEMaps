# CVE Maps: CNA to CWE Association Visualization

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
├── web/
│   ├── index.html                   # Landing page with navigation
│   ├── index-force.html             # Force-directed graph
│   ├── index-clusters.html          # Independent clusters view
│   ├── index-cwe-cooccurrence.html  # CWE co-occurrence network
│   ├── index-bipartite-top50.html   # Top 50 CNA-CWE bipartite
│   ├── index-cwe-hierarchy.html     # CWE hierarchy tree
│   ├── index-cwe-stars.html         # CWE star graphs
│   ├── index-cwe-circular.html      # Circular CWE layout
│   ├── index-cna-collaboration.html # CNA collaboration network
│   ├── index-mitre-ego.html         # MITRE ego network
│   └── data/
│       ├── cna_to_cwe_map.json      # Main graph data
│       ├── cwe_cooccurrence_map.json # CWE co-occurrence
│       ├── top_cna_cwe_bipartite.json # Bipartite layout
│       ├── cwe_hierarchy_tree.json   # Hierarchy tree
│       ├── cwe_star_graphs.json      # Star graphs
│       ├── cwe_circular_layout.json  # Circular layout
│       ├── cna_collaboration.json    # Collaboration network
│       └── mitre_ego_network.json    # MITRE ego network
├── build_graph.py                   # Main graph generation script
├── build_alternative_graphs.py      # Alternative visualizations
├── build_compact_graphs.py          # Compact NetworkX layouts
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

### 2. Visualization (`web/index.html`, `web/index-force.html`, `web/index-clusters.html`)
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

### 2. Force-Directed Network (`index-force.html`)
- All CNAs and CWEs in one interconnected graph
- 349 CNAs, 577 CWEs, 6,103 associations
- Drag nodes to explore relationships
- Click to highlight connections
- Real-time search filtering
- File size: 597KB

### 3. Independent Clusters (`index-clusters.html`)
- 409 isolated mini-networks (one per CNA)
- **CNA names displayed inside blue circles**
- Sort by size or filter by name/CWE
- Adjustable density slider
- CNA size scales with CWE count
- Drag CWEs within cluster boundaries
- **Optimized with 365-day filter**

### 4. CWE Co-occurrence Network (`index-cwe-cooccurrence.html`)
- Shows which CWEs commonly appear together in CVEs
- 577 CWE nodes, 903 co-occurrence edges
- Click to see common partners
- Node size reflects co-occurrence frequency
- File size: 121KB

### 5. Top 50 CNA-CWE Bipartite (`index-bipartite-top50.html`)
- Two-column layout: 50 most active CNAs (left), 603 CWEs (right)
- 4,175 associations clearly visible
- Bipartite graph layout for pattern recognition
- Vertical divider separates the two groups
- File size: 444KB

### 6. CWE Hierarchy Tree (`index-cwe-hierarchy.html`)
- 3-level tree structure: root → categories → CWEs
- 51 nodes organized hierarchically
- Color-coded by type (blue=root, purple=category, red=CWE)
- Node size reflects CVE count
- File size: 14KB

### 7. CWE Star Graphs (`index-cwe-stars.html`)
- Top 12 CWEs displayed as star centers
- 252 total nodes with CNAs radiating outward
- Shows which organizations focus on which weaknesses
- Multiple stars in grid layout
- File size: 71KB

### 8. Circular CWE Layout (`index-cwe-circular.html`)
- Top 40 CWEs arranged in a symmetric circle
- 227 interconnection edges
- Click to highlight neighbors
- Perfect for spotting central weaknesses
- File size: 26KB

### 9. CNA Collaboration Network (`index-cna-collaboration.html`)
- 396 CNAs connected by shared CWE focus areas
- 4,190 collaboration edges
- Reveals research interests and patterns
- Spring layout with pre-computed positions
- File size: 521KB

### 10. MITRE Ego Network (`index-mitre-ego.html`)
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
- NetworkX library
- Modern web browser with JavaScript enabled

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🙏 Acknowledgments

- [CVE Project](https://github.com/CVEProject/cvelistV5) for CVE data
- [D3.js](https://d3js.org/) for visualization
- [NetworkX](https://networkx.org/) for graph processing
- [Tailwind CSS](https://tailwindcss.com/) for styling

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

**Last Updated**: Auto-generated by GitHub Actions
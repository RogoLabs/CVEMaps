# CVE Maps - Quick Start Guide

## 🚀 Getting Started

### Option 1: Automated Deployment (Recommended)

This is the easiest way to get your CVE Map up and running with automatic updates.

1. **Enable GitHub Pages**:
   - Go to your repository on GitHub
   - Click **Settings** → **Pages**
   - Under "Source", select **GitHub Actions**
   - Save changes

2. **Trigger the Workflow**:
   - Go to the **Actions** tab
   - Click on "Update CVE Map Data" workflow
   - Click **Run workflow** → **Run workflow**
   
3. **Wait for Deployment** (10-15 minutes):
   - The workflow will clone ~200,000 CVE files
   - Parse all JSON files
   - Build the graph
   - Deploy to GitHub Pages

4. **View Your Site**:
   - Visit `https://rogolabs.github.io/CVEMaps/`
   - (Replace with your GitHub username/organization)

### Option 2: Local Testing

Test the system locally before deploying to GitHub Pages.

1. **Clone and Setup**:
   ```bash
   git clone https://github.com/RogoLabs/CVEMaps.git
   cd CVEMaps
   
   # Install Python dependencies
   pip install networkx
   ```

2. **Download CVE Data**:
   ```bash
   # Use the setup script
   chmod +x scripts/setup_cve_data.sh
   ./scripts/setup_cve_data.sh
   
   # Or manually:
   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve-data
   ```

3. **Build the Graphs**:
   ```bash
   # Build main graph
   python scripts/build_graph.py
   
   # Build alternative visualizations
   python scripts/build_alternative_graphs.py
   
   # Build compact layouts
   python scripts/build_compact_graphs.py
   
   # Build extended visualizations (vendors, CVSS, temporal)
   python scripts/build_extended_graphs.py
   ```
   
   Expected output:
   ```
   Starting to parse CVE files from: cve-data/cves
   Processed 10000 files...
   Processed 20000 files...
   ...
   Parsing complete!
   Total CVE files found: 200000+
   Files with CNA-CWE associations: ~80000
   Graph built successfully!
   CNA nodes: ~400
   CWE nodes: ~800
   Edges: ~15000
   ```

4. **Test Locally**:
   ```bash
   cd web
   python -m http.server 8000
   ```
   
   Open your browser to: `http://localhost:8000`

## 📋 Verification Checklist

After deployment, verify everything works:

- [ ] GitHub Actions workflow completed successfully
- [ ] Web page loads at your GitHub Pages URL
- [ ] Graph visualization renders (you should see blue and red nodes)
- [ ] Nodes are interactive (hover shows tooltips)
- [ ] Can pan, zoom, and drag nodes
- [ ] Clicking a node highlights its connections
- [ ] Info panel shows statistics
- [ ] "Last updated" timestamp is recent

## 🔧 Troubleshooting

### GitHub Actions Fails

**Error: "Graph data file not found"**
- Check the Python script logs in Actions
- Ensure NetworkX is installed correctly
- Verify the CVE repository cloned successfully

**Error: "Permission denied"**
- Go to Settings → Actions → General
- Under "Workflow permissions", select "Read and write permissions"
- Save and re-run the workflow

### Visualization Not Showing

**Blank page or "Loading..." forever**
- Check browser console for errors (F12)
- Verify `web/data/cna_to_cwe_map.json` exists
- Check if JSON file has actual data (not just placeholder)
- Try hard refresh: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)

**CORS errors in browser console**
- This happens when opening `index.html` directly as `file://`
- Use a local web server: `python -m http.server`
- Or deploy to GitHub Pages

### Graph Looks Strange

**Only a few nodes showing**
- Wait for the graph to finish loading
- Try the "Reset View" button
- Check that the JSON file has data

**Nodes flying everywhere**
- This is normal initially - the force simulation is settling
- Wait 5-10 seconds for stabilization
- Drag nodes to manually arrange them

## 🎨 Customization Ideas

### Change Update Frequency

Edit `.github/workflows/update_map.yml`:

```yaml
schedule:
  # Every 6 hours instead of 3
  - cron: '0 */6 * * *'
  
  # Daily at midnight UTC
  - cron: '0 0 * * *'
  
  # Weekly on Mondays at 9 AM
  - cron: '0 9 * * 1'
```

### Modify Visual Styling

Edit `web/index.html`:

```javascript
// Change node colors
.node.cna {
    fill: #10b981;  // Green instead of blue
}
.node.cwe {
    fill: #f59e0b;  // Orange instead of red
}

// Adjust node sizes
function nodeRadius(d) {
    return Math.max(8, Math.min(25, 5 + Math.sqrt(d.connections) * 2.5));
}

// Change background
#graph-container {
    background: linear-gradient(to bottom right, #1e1b4b, #312e81);
}
```

### Filter Data

Edit `scripts/build_graph.py` to focus on specific CNAs or CWEs:

```python
# Only include certain CNAs
ALLOWED_CNAS = ['cve@mitre.org', 'security@apache.org']

if cna in ALLOWED_CNAS:
    # ... process this CVE

# Only include certain CWE categories
if cwe.startswith('CWE-79') or cwe.startswith('CWE-89'):
    # ... include this CWE
```

## 📊 Understanding the Data

### Node Types

**Blue Nodes (CNAs)**:
- Organizations authorized to assign CVE IDs
- Examples: `cve@mitre.org`, `security@apache.org`, `psirt@cisco.com`
- Size indicates how many CWEs they report

**Red Nodes (CWEs)**:
- Standardized weakness categories
- Examples: `CWE-79` (XSS), `CWE-89` (SQL Injection)
- Size indicates how many CNAs report this weakness

### Edge Weights

The thickness/opacity of connections represents:
- How many times a CNA has reported a particular CWE
- Stronger connections = more frequent association
- Example: If MITRE has assigned 500 CVEs with CWE-79, that edge is very thick

## 🔄 Manual Updates

To manually update the data:

1. Go to **Actions** tab on GitHub
2. Select "Update CVE Map Data"
3. Click **Run workflow**
4. Select branch (usually `main`)
5. Click **Run workflow**

The site will update in ~10-15 minutes.

## 📈 Next Steps

- **Monitor**: Check the Actions tab weekly to ensure updates are running
- **Analyze**: Use the visualization to identify trends in vulnerability types
- **Extend**: Add more graph types (CVE-to-CPE, temporal analysis, etc.)
- **Share**: Add the GitHub Pages link to your README badge
- **Optimize**: Consider caching or filtering for faster builds

## 🆘 Need Help?

- Check existing GitHub Issues
- Review GitHub Actions logs for detailed error messages
- Open a new issue with:
  - What you tried
  - Error messages
  - Screenshots if applicable

---

**Pro Tip**: Star the repository to get notifications when the workflow runs!

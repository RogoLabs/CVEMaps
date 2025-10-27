# Quick Reference Guide

Quick reference for common CVEMaps tasks.

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/RogoLabs/CVEMaps.git
cd CVEMaps

# Install dependencies
pip install networkx

# Or install for development
pip install -e ".[dev]"
```

## 🔨 Building Visualizations

```bash
# Clone CVE data (first time only)
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve-data

# Build main graph
python build_graph.py

# Build alternative visualizations
python build_alternative_graphs.py

# Build compact layouts
python build_compact_graphs.py
```

## 🌐 Local Development

```bash
# Start local web server
cd web
python -m http.server 8000

# Visit in browser
open http://localhost:8000
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cvemaps

# Run specific test
pytest tests/test_build_graph.py
```

## 🎨 Code Quality

```bash
# Format code
black cvemaps/

# Lint code
ruff check cvemaps/

# Fix linting issues automatically
ruff check --fix cvemaps/

# Type check
mypy cvemaps/
```

## ⚙️ Configuration

### Via Environment Variables
```bash
export CVE_DATA_DIR="cve-data/cves"
export DAYS_BACK=365
export TOP_N_CNAS=50
python build_graph.py
```

### Via Python
```python
from cvemaps.config import Config

config = Config(
    CVE_DATA_DIR="custom-path",
    DAYS_BACK=180,
    TOP_N_CNAS=100
)
```

## 📦 Package Commands

```bash
# Build package
python -m build

# Install locally
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"
```

## 🐛 Troubleshooting

### CVE data not found
```bash
# Make sure you've cloned the CVE data
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve-data
```

### Import errors
```bash
# Install in development mode
pip install -e .
```

### Web visualizations not loading
```bash
# Check if data files exist
ls -lh web/data/

# Rebuild if needed
python build_graph.py
```

## 🔄 Updating CVE Data

```bash
cd cve-data
git pull --depth 1
cd ..
python build_graph.py
```

## 📊 Checking Statistics

```bash
# Count CVE files
find cve-data/cves -name "CVE-*.json" | wc -l

# Check output file sizes
du -h web/data/*.json
```

## 🚢 Deployment

### GitHub Actions (Automatic)
- Workflow runs every 3 hours automatically
- Or trigger manually: Actions → Update CVE Map Data → Run workflow

### Manual Deployment
```bash
# Build all visualizations
python build_graph.py
python build_alternative_graphs.py
python build_compact_graphs.py

# Commit and push
git add web/data/
git commit -m "Update visualizations"
git push

# GitHub Pages will auto-deploy
```

## 🔍 Common File Locations

```
CVEMaps/
├── build_graph.py              # Main graph builder
├── build_alternative_graphs.py # Alternative visualizations
├── build_compact_graphs.py     # Compact layouts
├── cvemaps/                    # Python package
│   ├── __init__.py
│   ├── config.py              # Configuration
│   └── build_graph.py         # Refactored builder
├── web/                        # Web visualizations
│   ├── index.html             # Landing page
│   ├── force-directed.html    # Main network
│   ├── clusters.html          # Cluster view
│   └── data/                  # Generated JSON files
├── README.md                   # Main documentation
├── CONTRIBUTING.md             # Contributor guide
├── CHANGELOG.md                # Version history
└── pyproject.toml              # Package configuration
```

## 💻 Git Workflow

```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes and commit
git add .
git commit -m "feat: add new feature"

# Push and create PR
git push origin feature/my-feature
```

## 📝 Commit Message Conventions

```
feat: new feature
fix: bug fix
docs: documentation changes
style: formatting changes
refactor: code refactoring
test: adding tests
chore: maintenance tasks
```

## 🔗 Useful Links

- **Live Demo**: https://rogolabs.github.io/CVEMaps/
- **Repository**: https://github.com/RogoLabs/CVEMaps
- **Issues**: https://github.com/RogoLabs/CVEMaps/issues
- **CVE Data**: https://github.com/CVEProject/cvelistV5

## 📚 Documentation

- `README.md` - Project overview
- `QUICKSTART.md` - Quick setup guide
- `CONTRIBUTING.md` - How to contribute
- `CODE_OF_CONDUCT.md` - Community standards
- `CHANGELOG.md` - Version history

## 🎯 Quick Tasks

### Add a New Visualization
1. Add generation function to appropriate builder script
2. Export JSON to `web/data/`
3. Create HTML file in `web/`
4. Add link in `web/index.html`
5. Update documentation

### Report a Bug
1. Go to Issues → New Issue
2. Choose "Bug Report" template
3. Fill in all sections
4. Submit

### Request a Feature
1. Go to Issues → New Issue
2. Choose "Feature Request" template
3. Describe use case and benefits
4. Submit

---

**Need more help?** Check the full documentation or open an issue!

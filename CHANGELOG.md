# Changelog

All notable changes to CVEMaps will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-27

### Added
- Initial public release
- Force-directed network visualization showing CNA-CWE relationships
- Independent clusters view with isolated mini-networks per CNA
- CWE co-occurrence network showing weaknesses that appear together
- Top 50 CNA-CWE bipartite layout
- CWE hierarchy tree visualization
- CWE star graphs for top weaknesses
- Circular CWE layout with interconnections
- CNA collaboration network based on shared CWEs
- MITRE ego network visualization
- Automated GitHub Actions workflow for data updates every 3 hours
- Interactive web interface with D3.js visualizations
- NetworkX-based graph generation from CVE data
- 365-day data filtering for optimal performance
- Comprehensive documentation and quick start guide
- Proper Python package structure with pyproject.toml
- Type hints and improved code quality
- Configuration management via environment variables
- Logging system for better debugging

### Changed
- Renamed visualization files from `index-*.html` to more descriptive names
- Refactored Python code into proper package structure
- Improved error handling and logging throughout codebase
- Updated documentation for clarity and completeness

### Technical Details
- Python 3.11+ support
- NetworkX 3.0+ for graph processing
- D3.js v7 for visualizations
- Tailwind CSS for styling
- Automated CI/CD with GitHub Actions

## [Unreleased]

### Planned Features
- Vendor vulnerability profiles
- CNA-vendor reporting map
- Sankey flow diagram
- Heatmap matrix visualization
- Interactive filtering and search improvements
- Export functionality (CSV, PNG, SVG)
- Historical trend analysis
- API endpoints for programmatic access

---

[1.0.0]: https://github.com/RogoLabs/CVEMaps/releases/tag/v1.0.0

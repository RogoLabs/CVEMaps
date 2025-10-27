# Contributing to CVEMaps

Thank you for your interest in contributing to CVEMaps! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## 🤝 Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/CVEMaps.git
   cd CVEMaps
   ```
3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/RogoLabs/CVEMaps.git
   ```

## 💻 Development Setup

### Prerequisites

- Python 3.11 or higher
- Git
- A text editor or IDE

### Installation

1. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install the package in editable mode with dev dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

3. **Clone the CVE data** (for testing):
   ```bash
   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cve-data
   ```

### Running the Build Scripts

```bash
# Build main graph
python -m cvemaps.build_graph

# Build alternative graphs
python build_alternative_graphs.py

# Build compact graphs
python build_compact_graphs.py
```

## 🎯 How to Contribute

### Types of Contributions

We welcome several types of contributions:

- **Bug fixes**: Fix issues in existing code
- **New features**: Add new visualization types or data processing capabilities
- **Documentation**: Improve README, add examples, write tutorials
- **Tests**: Add unit tests or integration tests
- **Performance improvements**: Optimize data processing or rendering
- **UI/UX**: Improve web interface design and usability

### Workflow

1. **Create a new branch** for your contribution:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following the coding standards

3. **Test your changes** thoroughly

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add new visualization type"
   ```

   Use conventional commit messages:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `style:` Code style changes (formatting)
   - `refactor:` Code refactoring
   - `test:` Adding tests
   - `chore:` Maintenance tasks

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** on GitHub

## 📐 Coding Standards

### Python Code

- Follow **PEP 8** style guidelines
- Use **type hints** for function arguments and return values
- Write **docstrings** for all functions and classes (Google style)
- Keep functions focused and under 50 lines when possible
- Use **meaningful variable names**

### Code Formatting

We use automated tools to maintain code quality:

```bash
# Format code with Black
black cvemaps/

# Lint with Ruff
ruff check cvemaps/

# Type check with mypy
mypy cvemaps/
```

### JavaScript/HTML

- Use consistent indentation (2 spaces)
- Follow existing D3.js patterns
- Add comments for complex visualization logic
- Ensure responsive design principles

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cvemaps

# Run specific test file
pytest tests/test_build_graph.py
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Use descriptive test function names: `test_parse_cve_files_filters_by_date()`
- Mock external dependencies (file system, network calls)
- Aim for high code coverage on core logic

Example test:

```python
def test_build_graph_creates_correct_node_types():
    """Test that build_graph creates CNA and CWE nodes correctly."""
    associations = {("cna1", "CWE-79"): 5}
    cna_names = {"cna1": "Example CNA"}
    
    graph = build_graph(associations, cna_names)
    
    assert graph.nodes["Example CNA"]["type"] == "cna"
    assert graph.nodes["CWE-79"]["type"] == "cwe"
```

## 🔄 Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features
3. **Ensure all tests pass**: `pytest`
4. **Update CHANGELOG.md** with your changes
5. **Fill out the PR template** completely
6. **Request review** from maintainers
7. **Address feedback** promptly and professionally

### PR Checklist

- [ ] Code follows the project's style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] Tests added/updated and passing
- [ ] No new warnings introduced
- [ ] CHANGELOG.md updated

## 🐛 Reporting Bugs

### Before Submitting

1. **Check existing issues** to avoid duplicates
2. **Test with the latest version** of the code
3. **Gather relevant information**:
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages and stack traces

### Bug Report Template

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. See error

**Expected behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
 - OS: [e.g., macOS, Linux, Windows]
 - Python version: [e.g., 3.11.5]
 - CVEMaps version: [e.g., 1.0.0]

**Additional context**
Any other relevant information.
```

## 💡 Suggesting Features

We love feature suggestions! Please:

1. **Check existing issues** for similar suggestions
2. **Describe the use case** clearly
3. **Explain the benefits** to users
4. **Consider implementation complexity**
5. **Provide examples** if possible

### Feature Request Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
What you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**Additional context**
Any other relevant information, mockups, or examples.
```

## 🎨 Adding New Visualizations

If you want to add a new visualization type:

1. **Create data generation function** in appropriate builder script
2. **Generate JSON output** in `web/data/`
3. **Create HTML visualization** in `web/`
4. **Add link** to landing page (`web/index.html`)
5. **Update documentation** (README.md)
6. **Add example screenshot** (optional)

See existing visualizations for reference patterns.

## 📚 Documentation

Good documentation is crucial! When contributing documentation:

- Use clear, concise language
- Provide code examples
- Add screenshots for visual features
- Keep README.md concise; move details to separate docs
- Update all affected documentation files

## 🏷️ Issue Labels

We use labels to organize issues:

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Documentation improvements
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `question`: Further information requested
- `wontfix`: Won't be worked on

## 🤔 Questions?

- **Open an issue** with the `question` label
- **Check existing issues** for answers
- **Review the README** and other documentation

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

## 🙏 Thank You!

Every contribution, no matter how small, is valuable. Thank you for helping make CVEMaps better!

---

**Happy Contributing! 🎉**

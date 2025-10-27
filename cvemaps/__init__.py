"""
CVEMaps - CVE to CWE Visualization System

This package provides tools for parsing CVE data and generating
interactive network visualizations showing relationships between
CVE Numbering Authorities (CNAs) and Common Weakness Enumerations (CWEs).
"""

__version__ = "1.0.0"
__author__ = "RogoLabs"
__license__ = "MIT"

from cvemaps.config import Config

__all__ = ["Config", "__version__"]

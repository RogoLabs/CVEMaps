"""Configuration settings for CVEMaps."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """Configuration for CVE data processing and graph generation."""

    # Data directories
    CVE_DATA_DIR: str = "cve-data/cves"
    WEB_DATA_DIR: str = "web/data"
    
    # Filtering parameters
    DAYS_BACK: int = 365  # Only process CVEs from last N days
    
    # Graph generation parameters
    MIN_SHARED_CWES: int = 10  # Minimum shared CWEs for collaboration network
    MIN_SHARED_REFS: int = 2   # Minimum shared references for reference network
    TEMPORAL_WINDOW_DAYS: int = 30  # Days window for temporal chaining
    
    # Compact graph parameters
    TOP_N_CNAS: int = 50  # Top N CNAs for bipartite graph
    TOP_N_CWES_HIERARCHY: int = 40  # Top N CWEs for hierarchy tree
    TOP_N_CWE_STARS: int = 12  # Number of star graphs to generate
    TOP_N_CWE_CIRCULAR: int = 40  # Top N CWEs for circular layout
    
    # Ego network parameters
    EGO_CNA_NAME: str = "mitre"  # CNA for ego network
    EGO_RADIUS: int = 1  # Radius for ego network
    
    # Processing parameters
    PROGRESS_INTERVAL: int = 10000  # Print progress every N files
    
    # Output parameters
    INDENT_JSON: int = 2  # JSON indentation level
    
    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls(
            CVE_DATA_DIR=os.getenv("CVE_DATA_DIR", cls.CVE_DATA_DIR),
            WEB_DATA_DIR=os.getenv("WEB_DATA_DIR", cls.WEB_DATA_DIR),
            DAYS_BACK=int(os.getenv("DAYS_BACK", cls.DAYS_BACK)),
            MIN_SHARED_CWES=int(os.getenv("MIN_SHARED_CWES", cls.MIN_SHARED_CWES)),
            MIN_SHARED_REFS=int(os.getenv("MIN_SHARED_REFS", cls.MIN_SHARED_REFS)),
            TEMPORAL_WINDOW_DAYS=int(os.getenv("TEMPORAL_WINDOW_DAYS", cls.TEMPORAL_WINDOW_DAYS)),
            TOP_N_CNAS=int(os.getenv("TOP_N_CNAS", cls.TOP_N_CNAS)),
            TOP_N_CWES_HIERARCHY=int(os.getenv("TOP_N_CWES_HIERARCHY", cls.TOP_N_CWES_HIERARCHY)),
            TOP_N_CWE_STARS=int(os.getenv("TOP_N_CWE_STARS", cls.TOP_N_CWE_STARS)),
            TOP_N_CWE_CIRCULAR=int(os.getenv("TOP_N_CWE_CIRCULAR", cls.TOP_N_CWE_CIRCULAR)),
            EGO_CNA_NAME=os.getenv("EGO_CNA_NAME", cls.EGO_CNA_NAME),
            EGO_RADIUS=int(os.getenv("EGO_RADIUS", cls.EGO_RADIUS)),
            PROGRESS_INTERVAL=int(os.getenv("PROGRESS_INTERVAL", cls.PROGRESS_INTERVAL)),
        )
    
    def get_cve_data_path(self) -> Path:
        """Get Path object for CVE data directory."""
        return Path(self.CVE_DATA_DIR)
    
    def get_web_data_path(self) -> Path:
        """Get Path object for web data directory."""
        return Path(self.WEB_DATA_DIR)
    
    def ensure_output_dir(self) -> None:
        """Ensure the output directory exists."""
        self.get_web_data_path().mkdir(parents=True, exist_ok=True)

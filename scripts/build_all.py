#!/usr/bin/env python3
"""
Unified Build Script for CVEMaps
Runs all graph generation scripts in the correct order.
"""

import os
import sys
import subprocess
from pathlib import Path

# Get the scripts directory
SCRIPTS_DIR = Path(__file__).parent
REPO_ROOT = SCRIPTS_DIR.parent

# Build scripts in order of execution
BUILD_SCRIPTS = [
    "build_graph.py",              # Main CNA-CWE graph
    "build_alternative_graphs.py",  # Alternative visualizations
    "build_compact_graphs.py",      # Compact layouts
    "build_extended_graphs.py",    # Extended visualizations (CVSS, temporal, etc.)
]

# Post-processing scripts
POST_PROCESS_SCRIPTS = [
    "optimize_data.py",            # Optimize large data files
]


def run_script(script_name):
    """Run a build script and return success status."""
    script_path = SCRIPTS_DIR / script_name
    
    if not script_path.exists():
        print(f"❌ Script not found: {script_name}")
        return False
    
    print(f"\n{'='*60}")
    print(f"Running: {script_name}")
    print(f"{'='*60}\n")
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=REPO_ROOT,
            check=True,
            text=True
        )
        print(f"\n✅ {script_name} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {script_name} failed with exit code {e.returncode}")
        return False
    except Exception as e:
        print(f"\n❌ Error running {script_name}: {e}")
        return False


def main():
    """Main execution function."""
    print("="*60)
    print("CVEMaps - Unified Build Script")
    print("="*60)
    print(f"\nRepository root: {REPO_ROOT}")
    print(f"Scripts directory: {SCRIPTS_DIR}")
    print(f"Scripts to run: {len(BUILD_SCRIPTS)}")
    print()
    
    # Check CVE data directory exists
    cve_data_dir = REPO_ROOT / "cve-data"
    if not cve_data_dir.exists():
        print("⚠️  WARNING: CVE data directory not found!")
        print(f"   Expected location: {cve_data_dir}")
        print("\nPlease run the setup script first:")
        print("  ./scripts/setup_cve_data.sh")
        print("\nOr set CVE_DATA_DIR environment variable to point to your CVE data.")
        sys.exit(1)
    
    print(f"✓ CVE data directory found: {cve_data_dir}\n")
    
    # Run all build scripts
    results = {}
    
    print("="*60)
    print("Phase 1: Building Graphs")
    print("="*60)
    
    for script in BUILD_SCRIPTS:
        success = run_script(script)
        results[script] = success
        
        # Stop if a critical script fails
        if not success and script in ["build_graph.py"]:
            print(f"\n❌ Critical script failed: {script}")
            print("Stopping build process.")
            break
    
    # Run post-processing scripts
    if all(results.values()):
        print("\n" + "="*60)
        print("Phase 2: Post-Processing")
        print("="*60)
        
        for script in POST_PROCESS_SCRIPTS:
            success = run_script(script)
            results[script] = success
    
    # Print summary
    print("\n" + "="*60)
    print("Build Summary")
    print("="*60)
    
    for script, success in results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"  {status}: {script}")
    
    total = len(results)
    successful = sum(1 for s in results.values() if s)
    
    print(f"\nTotal: {successful}/{total} scripts completed successfully")
    
    if successful == total:
        print("\n🎉 All builds completed successfully!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total - successful} script(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

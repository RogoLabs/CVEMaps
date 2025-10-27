#!/usr/bin/env python3
"""
Optimize Large Data Files
Reduces file sizes for web visualization by:
- Aggregating temporal data by month instead of individual CVEs
- Limiting product/vendor data to top N entries
- Removing unnecessary fields
"""

import json
import os
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DATA_DIR = REPO_ROOT / "web" / "data"

# Files to optimize (filename, max size in MB)
FILES_TO_OPTIMIZE = {
    "cve_temporal_map.json": 5,          # 497MB -> aggregate by month
    "product_dependency_map.json": 2,    # 51MB -> top 1000 products
    "product_cwe_map.json": 2,           # 7.8MB -> top 500 products
    "vendor_cwe_map.json": 1,            # 2.7MB -> top 200 vendors
    "cna_vendor_map.json": 1,            # 1.8MB -> already reasonable, might compress
    "cve_references_map.json": 2,        # 2.8MB -> remove if not used
}


def get_file_size_mb(filepath):
    """Get file size in MB."""
    return os.path.getsize(filepath) / (1024 * 1024)


def optimize_temporal_map(input_file, output_file):
    """Aggregate temporal data by month instead of individual CVEs."""
    print(f"  Optimizing temporal map...")
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Aggregate by month
    monthly_stats = defaultdict(lambda: {"count": 0, "cnas": defaultdict(int), "cwes": defaultdict(int)})
    
    for node in data.get("nodes", []):
        if node.get("type") == "cve":
            # Extract year-month from CVE ID (CVE-YYYY-...)
            cve_id = node.get("id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year_month = parts[1]  # Just use year for now
                    monthly_stats[year_month]["count"] += 1
                    if "cna" in node:
                        monthly_stats[year_month]["cnas"][node["cna"]] += 1
    
    # Convert to timeline format
    timeline = []
    for period, stats in sorted(monthly_stats.items()):
        timeline.append({
            "period": period,
            "count": stats["count"],
            "top_cnas": sorted(stats["cnas"].items(), key=lambda x: x[1], reverse=True)[:10]
        })
    
    optimized = {
        "timeline": timeline,
        "total_cves": sum(s["count"] for s in monthly_stats.values()),
        "metadata": {
            "description": "Aggregated CVE timeline by year",
            "optimized": True
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(optimized, f, indent=2)
    
    return get_file_size_mb(output_file)


def optimize_product_map(input_file, output_file, top_n=500):
    """Keep only top N products by CVE count."""
    print(f"  Optimizing product map (top {top_n})...")
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Count connections per product
    product_counts = defaultdict(int)
    for link in data.get("links", []):
        if link.get("source"):
            product_counts[link["source"]] += link.get("value", 1)
        if link.get("target"):
            product_counts[link["target"]] += link.get("value", 1)
    
    # Get top N products
    top_products = set(p for p, _ in sorted(product_counts.items(), key=lambda x: x[1], reverse=True)[:top_n])
    
    # Filter nodes and links
    filtered_nodes = [n for n in data.get("nodes", []) if n.get("id") in top_products or n.get("type") == "cwe"]
    filtered_links = [l for l in data.get("links", []) 
                      if l.get("source") in top_products or l.get("target") in top_products]
    
    optimized = {
        "nodes": filtered_nodes,
        "links": filtered_links,
        "metadata": {
            **data.get("metadata", {}),
            "optimized": True,
            "top_n": top_n
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(optimized, f, indent=2)
    
    return get_file_size_mb(output_file)


def optimize_vendor_map(input_file, output_file, top_n=200):
    """Keep only top N vendors by CVE count."""
    print(f"  Optimizing vendor map (top {top_n})...")
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Count connections per vendor
    vendor_counts = defaultdict(int)
    for link in data.get("links", []):
        source = link.get("source")
        vendor_counts[source] += link.get("weight", 1)
    
    # Get top N vendors
    top_vendors = set(v for v, _ in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:top_n])
    
    # Filter nodes and links
    filtered_nodes = [n for n in data.get("nodes", []) 
                      if n.get("id") in top_vendors or n.get("node_type") == "cwe"]
    node_ids = {n["id"] for n in filtered_nodes}
    filtered_links = [l for l in data.get("links", []) 
                      if l.get("source") in node_ids and l.get("target") in node_ids]
    
    optimized = {
        "nodes": filtered_nodes,
        "links": filtered_links,
        "metadata": {
            **data.get("metadata", {}),
            "optimized": True,
            "top_n": top_n
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(optimized, f, indent=2)
    
    return get_file_size_mb(output_file)


def delete_unused_file(filepath):
    """Delete a file that's too large and not used."""
    print(f"  Deleting unused file...")
    os.remove(filepath)
    print(f"  ✓ Deleted")


def main():
    """Main execution function."""
    print("="*60)
    print("CVEMaps - Data Optimization")
    print("="*60)
    print()
    
    files_processed = 0
    total_saved = 0
    
    for filename, max_size_mb in FILES_TO_OPTIMIZE.items():
        filepath = DATA_DIR / filename
        
        if not filepath.exists():
            print(f"⊘ {filename}: Not found, skipping")
            continue
        
        current_size = get_file_size_mb(filepath)
        print(f"\n📄 {filename}")
        print(f"  Current size: {current_size:.2f} MB")
        
        if current_size <= max_size_mb:
            print(f"  ✓ Already optimized (under {max_size_mb} MB)")
            continue
        
        # Backup original
        backup_path = filepath.with_suffix('.json.backup')
        if not backup_path.exists():
            print(f"  Creating backup...")
            with open(filepath, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
        
        # Optimize based on file type
        try:
            if "temporal" in filename:
                new_size = optimize_temporal_map(filepath, filepath)
            elif "product" in filename and "dependency" in filename:
                # Product dependency is very large, limit heavily
                new_size = optimize_product_map(filepath, filepath, top_n=200)
            elif "product" in filename:
                new_size = optimize_product_map(filepath, filepath, top_n=500)
            elif "vendor" in filename and "cna" not in filename:
                new_size = optimize_vendor_map(filepath, filepath, top_n=200)
            elif "references" in filename:
                # References map might not be used in visualizations
                delete_unused_file(filepath)
                new_size = 0
            else:
                print(f"  ⚠️  No optimization strategy defined")
                continue
            
            if new_size > 0:
                saved = current_size - new_size
                total_saved += saved
                print(f"  New size: {new_size:.2f} MB")
                print(f"  Saved: {saved:.2f} MB ({(saved/current_size)*100:.1f}%)")
                print(f"  ✓ Optimized")
            
            files_processed += 1
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            # Restore from backup if optimization failed
            if backup_path.exists():
                print(f"  Restoring from backup...")
                with open(backup_path, 'rb') as src, open(filepath, 'wb') as dst:
                    dst.write(src.read())
    
    print("\n" + "="*60)
    print("Optimization Summary")
    print("="*60)
    print(f"Files processed: {files_processed}")
    print(f"Total space saved: {total_saved:.2f} MB")
    print()


if __name__ == "__main__":
    main()

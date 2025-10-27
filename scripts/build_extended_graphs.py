#!/usr/bin/env python3
"""
Extended CVE Map Builder
Builds additional visualizations including vendor profiles, CVSS distributions,
temporal analysis, Sankey diagrams, and heatmaps.
"""

import os
import json
import networkx as nx
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
import re
import sys
from pathlib import Path

# Add current directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import Config


def parse_cve_extended_data(data_dir, days_back=365):
    """
    Parse CVE files and extract extended data including vendors, CVSS scores, and dates.
    
    Returns:
        dict with keys:
        - cna_cwe_associations: defaultdict of (CNA, CWE) -> count
        - vendor_cwe_associations: defaultdict of (vendor, CWE) -> count  
        - cna_vendor_associations: defaultdict of (CNA, vendor) -> count
        - cvss_data: list of dicts with CVE details
        - temporal_data: list of dicts with publication dates
        - cna_names: dict of CNA UUID -> short name
    """
    cna_cwe_assoc = defaultdict(int)
    vendor_cwe_assoc = defaultdict(int)
    cna_vendor_assoc = defaultdict(int)
    cvss_data = []
    temporal_data = []
    cna_names = {}
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    
    print(f"Parsing CVE files from: {data_dir}")
    print(f"Date filter: {cutoff_date.strftime('%Y-%m-%d')} onwards")
    
    total_files = 0
    parsed_files = 0
    
    for root, dirs, files in os.walk(data_dir):
        for filename in files:
            if not filename.startswith("CVE-") or not filename.endswith(".json"):
                continue
            
            total_files += 1
            filepath = os.path.join(root, filename)
            
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)
                
                cve_id = cve_data.get("cveMetadata", {}).get("cveId", "Unknown")
                cve_metadata = cve_data.get("cveMetadata", {})
                
                # Parse publication date
                date_published = cve_metadata.get("datePublished")
                pub_date = None
                if date_published:
                    try:
                        pub_date = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
                        if pub_date < cutoff_date:
                            continue
                    except (ValueError, AttributeError):
                        pass
                
                # Extract CNA
                cna_uuid = cve_metadata.get("assignerOrgId")
                cna_short_name = cve_metadata.get("assignerShortName")
                if not cna_uuid:
                    continue
                
                if cna_short_name and cna_uuid not in cna_names:
                    cna_names[cna_uuid] = cna_short_name
                elif cna_uuid not in cna_names:
                    cna_names[cna_uuid] = cna_uuid
                
                # Extract CWEs
                containers = cve_data.get("containers", {})
                cwes_found = set()
                
                # CNA container
                cna_container = containers.get("cna", {})
                problem_types = cna_container.get("problemTypes", [])
                for problem_type in problem_types:
                    descriptions = problem_type.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("type") == "CWE":
                            cwe_value = desc.get("cweId") or desc.get("value")
                            if cwe_value and cwe_value.startswith("CWE-"):
                                cwes_found.add(cwe_value)
                
                # ADP containers
                adp_containers = containers.get("adp", [])
                if isinstance(adp_containers, list):
                    for adp in adp_containers:
                        adp_problem_types = adp.get("problemTypes", [])
                        for problem_type in adp_problem_types:
                            descriptions = problem_type.get("descriptions", [])
                            for desc in descriptions:
                                if desc.get("type") == "CWE":
                                    cwe_value = desc.get("cweId") or desc.get("value")
                                    if cwe_value and cwe_value.startswith("CWE-"):
                                        cwes_found.add(cwe_value)
                
                # Extract vendors from affected products
                vendors = set()
                affected = cna_container.get("affected", [])
                for item in affected:
                    vendor = item.get("vendor", "").strip()
                    if vendor and vendor.lower() not in ["n/a", "unknown", ""]:
                        # Clean vendor name
                        vendor = vendor.lower().replace("_", " ").title()
                        vendors.add(vendor)
                
                # Extract CVSS scores
                metrics = cna_container.get("metrics", [])
                cvss_scores = []
                for metric in metrics:
                    # CVSS v3.x
                    if "cvssV3_1" in metric:
                        cvss_v3 = metric["cvssV3_1"]
                        cvss_scores.append({
                            "version": "3.1",
                            "baseScore": cvss_v3.get("baseScore"),
                            "baseSeverity": cvss_v3.get("baseSeverity"),
                            "vectorString": cvss_v3.get("vectorString")
                        })
                    elif "cvssV3_0" in metric:
                        cvss_v3 = metric["cvssV3_0"]
                        cvss_scores.append({
                            "version": "3.0",
                            "baseScore": cvss_v3.get("baseScore"),
                            "baseSeverity": cvss_v3.get("baseSeverity"),
                            "vectorString": cvss_v3.get("vectorString")
                        })
                    # CVSS v2
                    elif "cvssV2_0" in metric:
                        cvss_v2 = metric["cvssV2_0"]
                        cvss_scores.append({
                            "version": "2.0",
                            "baseScore": cvss_v2.get("baseScore"),
                            "baseSeverity": None,  # v2 doesn't have severity labels
                            "vectorString": cvss_v2.get("vectorString")
                        })
                
                # Record associations
                for cwe in cwes_found:
                    cna_cwe_assoc[(cna_uuid, cwe)] += 1
                    
                    for vendor in vendors:
                        vendor_cwe_assoc[(vendor, cwe)] += 1
                
                for vendor in vendors:
                    cna_vendor_assoc[(cna_uuid, vendor)] += 1
                
                # Store CVSS data
                if cvss_scores:
                    for cvss in cvss_scores:
                        cvss_data.append({
                            "cve_id": cve_id,
                            "cna": cna_names[cna_uuid],
                            "cwes": list(cwes_found),
                            "vendors": list(vendors),
                            "cvss_version": cvss["version"],
                            "base_score": cvss["baseScore"],
                            "severity": cvss["baseSeverity"],
                            "vector": cvss["vectorString"]
                        })
                
                # Store temporal data
                if pub_date:
                    temporal_data.append({
                        "cve_id": cve_id,
                        "cna": cna_names[cna_uuid],
                        "date": pub_date.strftime("%Y-%m-%d"),
                        "year": pub_date.year,
                        "month": pub_date.month,
                        "cwes": list(cwes_found),
                        "vendors": list(vendors)
                    })
                
                parsed_files += 1
                
            except Exception as e:
                continue
            
            if total_files % 10000 == 0:
                print(f"Processed {total_files} files...")
    
    print(f"\nParsing complete!")
    print(f"Total files: {total_files}")
    print(f"Parsed successfully: {parsed_files}")
    print(f"CNA-CWE associations: {len(cna_cwe_assoc)}")
    print(f"Vendor-CWE associations: {len(vendor_cwe_assoc)}")
    print(f"CNA-Vendor associations: {len(cna_vendor_assoc)}")
    print(f"CVEs with CVSS data: {len(cvss_data)}")
    print(f"CVEs with temporal data: {len(temporal_data)}")
    
    return {
        "cna_cwe_associations": cna_cwe_assoc,
        "vendor_cwe_associations": vendor_cwe_assoc,
        "cna_vendor_associations": cna_vendor_assoc,
        "cvss_data": cvss_data,
        "temporal_data": temporal_data,
        "cna_names": cna_names
    }


def build_vendor_vulnerability_profiles(data, output_file, top_n=50):
    """Build bipartite graph of top vendors and their most common CWEs."""
    vendor_cwe = data["vendor_cwe_associations"]
    
    # Get top vendors by total CVE count
    vendor_counts = defaultdict(int)
    for (vendor, cwe), count in vendor_cwe.items():
        vendor_counts[vendor] += count
    
    top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    top_vendor_names = {v[0] for v in top_vendors}
    
    # Build bipartite graph
    G = nx.Graph()
    
    for (vendor, cwe), count in vendor_cwe.items():
        if vendor in top_vendor_names:
            G.add_node(vendor, bipartite=0, node_type="vendor", cve_count=vendor_counts[vendor])
            G.add_node(cwe, bipartite=1, node_type="cwe")
            G.add_edge(vendor, cwe, weight=count)
    
    # Position nodes in bipartite layout
    vendors = [n for n, d in G.nodes(data=True) if d["bipartite"] == 0]
    cwes = [n for n, d in G.nodes(data=True) if d["bipartite"] == 1]
    
    pos = {}
    for i, vendor in enumerate(vendors):
        pos[vendor] = {"x": 0, "y": i * 1000 / len(vendors) if len(vendors) > 1 else 500}
    for i, cwe in enumerate(cwes):
        pos[cwe] = {"x": 1000, "y": i * 1000 / len(cwes) if len(cwes) > 1 else 500}
    
    # Export to JSON
    graph_data = {
        "nodes": [
            {
                "id": node,
                "label": node,
                "bipartite": G.nodes[node]["bipartite"],
                "node_type": G.nodes[node]["node_type"],
                "x": pos[node]["x"],
                "y": pos[node]["y"]
            }
            for node in G.nodes()
        ],
        "links": [
            {
                "source": u,
                "target": v,
                "weight": G[u][v]["weight"]
            }
            for u, v in G.edges()
        ],
        "metadata": {
            "description": "Top vendors linked to their most common vulnerability types",
            "vendor_count": len(vendors),
            "cwe_count": len(cwes),
            "edge_count": G.number_of_edges()
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(graph_data, f, indent=2)
    
    print(f"✓ Vendor vulnerability profiles saved to {output_file}")
    print(f"  {len(vendors)} vendors, {len(cwes)} CWEs, {G.number_of_edges()} connections")


def build_cna_vendor_map(data, output_file, top_cnas=50, top_vendors=100):
    """Build bipartite graph showing which CNAs report on which vendors."""
    cna_vendor = data["cna_vendor_associations"]
    cna_names = data["cna_names"]
    
    # Get top CNAs and vendors
    cna_counts = defaultdict(int)
    vendor_counts = defaultdict(int)
    
    for (cna_uuid, vendor), count in cna_vendor.items():
        cna_counts[cna_uuid] += count
        vendor_counts[vendor] += count
    
    top_cna_uuids = {c[0] for c in sorted(cna_counts.items(), key=lambda x: x[1], reverse=True)[:top_cnas]}
    top_vendor_names = {v[0] for v in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:top_vendors]}
    
    # Build bipartite graph
    G = nx.Graph()
    
    for (cna_uuid, vendor), count in cna_vendor.items():
        if cna_uuid in top_cna_uuids and vendor in top_vendor_names:
            cna_name = cna_names.get(cna_uuid, cna_uuid)
            G.add_node(cna_name, bipartite=0, node_type="cna")
            G.add_node(vendor, bipartite=1, node_type="vendor")
            G.add_edge(cna_name, vendor, weight=count)
    
    # Position nodes
    cnas = [n for n, d in G.nodes(data=True) if d["bipartite"] == 0]
    vendors = [n for n, d in G.nodes(data=True) if d["bipartite"] == 1]
    
    pos = {}
    for i, cna in enumerate(cnas):
        pos[cna] = {"x": 0, "y": i * 1000 / len(cnas) if len(cnas) > 1 else 500}
    for i, vendor in enumerate(vendors):
        pos[vendor] = {"x": 1000, "y": i * 1000 / len(vendors) if len(vendors) > 1 else 500}
    
    # Export
    graph_data = {
        "nodes": [
            {
                "id": node,
                "label": node,
                "bipartite": G.nodes[node]["bipartite"],
                "node_type": G.nodes[node]["node_type"],
                "x": pos[node]["x"],
                "y": pos[node]["y"]
            }
            for node in G.nodes()
        ],
        "links": [
            {
                "source": u,
                "target": v,
                "weight": G[u][v]["weight"]
            }
            for u, v in G.edges()
        ],
        "metadata": {
            "description": "CNAs reporting vulnerabilities for specific vendors",
            "cna_count": len(cnas),
            "vendor_count": len(vendors),
            "edge_count": G.number_of_edges()
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(graph_data, f, indent=2)
    
    print(f"✓ CNA-Vendor reporting map saved to {output_file}")
    print(f"  {len(cnas)} CNAs, {len(vendors)} vendors, {G.number_of_edges()} connections")


def build_sankey_diagram_data(data, output_file, top_cnas=20, top_cwes=30):
    """Build Sankey diagram data showing flow from CNAs to CWEs."""
    cna_cwe = data["cna_cwe_associations"]
    cna_names = data["cna_names"]
    
    # Get top CNAs and CWEs
    cna_counts = defaultdict(int)
    cwe_counts = defaultdict(int)
    
    for (cna_uuid, cwe), count in cna_cwe.items():
        cna_counts[cna_uuid] += count
        cwe_counts[cwe] += count
    
    top_cna_uuids = {c[0] for c in sorted(cna_counts.items(), key=lambda x: x[1], reverse=True)[:top_cnas]}
    top_cwe_ids = {c[0] for c in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:top_cwes]}
    
    # Build node list
    nodes = []
    node_map = {}
    idx = 0
    
    for cna_uuid in top_cna_uuids:
        cna_name = cna_names.get(cna_uuid, cna_uuid)
        nodes.append({"name": cna_name, "type": "cna"})
        node_map[cna_name] = idx
        idx += 1
    
    for cwe in top_cwe_ids:
        nodes.append({"name": cwe, "type": "cwe"})
        node_map[cwe] = idx
        idx += 1
    
    # Build links
    links = []
    for (cna_uuid, cwe), count in cna_cwe.items():
        if cna_uuid in top_cna_uuids and cwe in top_cwe_ids:
            cna_name = cna_names.get(cna_uuid, cna_uuid)
            links.append({
                "source": node_map[cna_name],
                "target": node_map[cwe],
                "value": count
            })
    
    sankey_data = {
        "nodes": nodes,
        "links": links,
        "metadata": {
            "description": "Flow from CNAs to CWEs",
            "cna_count": len(top_cna_uuids),
            "cwe_count": len(top_cwe_ids),
            "total_flow": sum(link["value"] for link in links)
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(sankey_data, f, indent=2)
    
    print(f"✓ Sankey diagram data saved to {output_file}")
    print(f"  {len(nodes)} nodes, {len(links)} flows")


def build_heatmap_matrix(data, output_file, top_cnas=30, top_cwes=40):
    """Build heatmap matrix data for CNAs vs CWEs."""
    cna_cwe = data["cna_cwe_associations"]
    cna_names = data["cna_names"]
    
    # Get top CNAs and CWEs
    cna_counts = defaultdict(int)
    cwe_counts = defaultdict(int)
    
    for (cna_uuid, cwe), count in cna_cwe.items():
        cna_counts[cna_uuid] += count
        cwe_counts[cwe] += count
    
    top_cnas = sorted(cna_counts.items(), key=lambda x: x[1], reverse=True)[:top_cnas]
    top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:top_cwes]
    
    cna_list = [cna_names.get(c[0], c[0]) for c in top_cnas]
    cwe_list = [c[0] for c in top_cwes]
    
    # Build matrix
    matrix = []
    for cna_uuid, _ in top_cnas:
        row = []
        for cwe, _ in top_cwes:
            count = cna_cwe.get((cna_uuid, cwe), 0)
            row.append(count)
        matrix.append(row)
    
    heatmap_data = {
        "cnas": cna_list,
        "cwes": cwe_list,
        "matrix": matrix,
        "metadata": {
            "description": "Heatmap of CNAs vs CWEs",
            "cna_count": len(cna_list),
            "cwe_count": len(cwe_list),
            "max_value": max(max(row) for row in matrix) if matrix else 0
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(heatmap_data, f, indent=2)
    
    print(f"✓ Heatmap matrix saved to {output_file}")
    print(f"  {len(cna_list)}×{len(cwe_list)} matrix")


def build_cvss_severity_distribution(data, output_file):
    """Build CVSS severity distribution data."""
    cvss_data = data["cvss_data"]
    
    # Count by severity
    severity_counts = Counter()
    severity_by_cna = defaultdict(lambda: Counter())
    severity_by_cwe = defaultdict(lambda: Counter())
    
    for item in cvss_data:
        severity = item["severity"] or "Unknown"
        severity_counts[severity] += 1
        severity_by_cna[item["cna"]][severity] += 1
        for cwe in item["cwes"]:
            severity_by_cwe[cwe][severity] += 1
    
    # Distribution by score ranges
    score_ranges = {
        "None (0.0)": 0,
        "Low (0.1-3.9)": 0,
        "Medium (4.0-6.9)": 0,
        "High (7.0-8.9)": 0,
        "Critical (9.0-10.0)": 0
    }
    
    for item in cvss_data:
        score = item["base_score"]
        if score == 0:
            score_ranges["None (0.0)"] += 1
        elif score < 4.0:
            score_ranges["Low (0.1-3.9)"] += 1
        elif score < 7.0:
            score_ranges["Medium (4.0-6.9)"] += 1
        elif score < 9.0:
            score_ranges["High (7.0-8.9)"] += 1
        else:
            score_ranges["Critical (9.0-10.0)"] += 1
    
    # Top CNAs by severity
    top_critical_cnas = sorted(
        [(cna, counts["CRITICAL"]) for cna, counts in severity_by_cna.items()],
        key=lambda x: x[1],
        reverse=True
    )[:20]
    
    cvss_distribution = {
        "severity_counts": dict(severity_counts),
        "score_ranges": score_ranges,
        "top_critical_cnas": [{"cna": cna, "count": count} for cna, count in top_critical_cnas],
        "total_cves": len(cvss_data),
        "metadata": {
            "description": "CVSS severity distribution across all CVEs"
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(cvss_distribution, f, indent=2)
    
    print(f"✓ CVSS severity distribution saved to {output_file}")
    print(f"  {len(cvss_data)} CVEs with CVSS scores")


def build_temporal_trends(data, output_file):
    """Build temporal analysis data showing CVE trends over time."""
    temporal_data = data["temporal_data"]
    
    # Count by month
    monthly_counts = defaultdict(int)
    monthly_by_cna = defaultdict(lambda: defaultdict(int))
    monthly_by_cwe = defaultdict(lambda: defaultdict(int))
    
    for item in temporal_data:
        year_month = f"{item['year']}-{item['month']:02d}"
        monthly_counts[year_month] += 1
        monthly_by_cna[item["cna"]][year_month] += 1
        for cwe in item["cwes"]:
            monthly_by_cwe[cwe][year_month] += 1
    
    # Sort by date
    sorted_months = sorted(monthly_counts.keys())
    
    # Top CNAs for timeline
    cna_totals = defaultdict(int)
    for item in temporal_data:
        cna_totals[item["cna"]] += 1
    top_cnas = [cna for cna, _ in sorted(cna_totals.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    timeline_data = {
        "monthly_totals": {month: monthly_counts[month] for month in sorted_months},
        "top_cnas": top_cnas,
        "cna_timelines": {
            cna: {month: monthly_by_cna[cna].get(month, 0) for month in sorted_months}
            for cna in top_cnas
        },
        "metadata": {
            "description": "CVE publication trends over time",
            "total_cves": len(temporal_data),
            "date_range": f"{sorted_months[0]} to {sorted_months[-1]}" if sorted_months else "N/A"
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(timeline_data, f, indent=2)
    
    print(f"✓ Temporal trends saved to {output_file}")
    print(f"  {len(sorted_months)} months of data")


def main():
    """Main execution function."""
    # Load configuration
    config = Config.from_env()
    
    cve_data_dir = config.CVE_DATA_DIR
    output_dir = config.WEB_DATA_DIR
    days_back = config.DAYS_BACK
    
    if not os.path.exists(cve_data_dir):
        print(f"ERROR: CVE data directory not found: {cve_data_dir}")
        print("\nTo set up CVE data, run:")
        print("  git clone https://github.com/CVEProject/cvelistV5.git cve-data")
        print("\nOr set CVE_DATA_DIR environment variable to point to your CVE data location.")
        sys.exit(1)
    
    config.ensure_output_dir()
    
    print("=" * 60)
    print("Building Extended CVE Visualizations")
    print("=" * 60)
    
    # Parse data
    print("\n[1/7] Parsing CVE data...")
    data = parse_cve_extended_data(cve_data_dir, days_back)
    
    # Build visualizations
    print("\n[2/7] Building vendor vulnerability profiles...")
    build_vendor_vulnerability_profiles(data, f"{output_dir}/vendor_vulnerability_profiles.json")
    
    print("\n[3/7] Building CNA-vendor reporting map...")
    build_cna_vendor_map(data, f"{output_dir}/cna_vendor_map.json")
    
    print("\n[4/7] Building Sankey diagram data...")
    build_sankey_diagram_data(data, f"{output_dir}/sankey_flow.json")
    
    print("\n[5/7] Building heatmap matrix...")
    build_heatmap_matrix(data, f"{output_dir}/heatmap_matrix.json")
    
    print("\n[6/7] Building CVSS severity distribution...")
    build_cvss_severity_distribution(data, f"{output_dir}/cvss_severity_distribution.json")
    
    print("\n[7/7] Building temporal trends...")
    build_temporal_trends(data, f"{output_dir}/temporal_trends.json")
    
    print("\n" + "=" * 60)
    print("✓ All extended visualizations built successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CVE Map Builder
Parses CVE JSON files from cvelistV5 repository and builds a NetworkX graph
mapping CNAs (CVE Numbering Authorities) to CWEs (Common Weakness Enumerations).
"""

import os
import json
import networkx as nx
from collections import defaultdict
from datetime import datetime, timedelta


def parse_cve_files(data_dir="cve-data/cves", days_back=365):
    """
    Recursively walk through CVE data directory and extract CNA-CWE associations.
    Only includes CVEs published within the last N days.
    
    Args:
        data_dir: Path to the CVE data directory
        days_back: Number of days back to include (default: 365 for last year)
        
    Returns:
        tuple: (associations dict, cna_names dict mapping UUID to short name)
    """
    associations = defaultdict(int)
    cna_names = {}  # Map UUID to human-readable name
    total_files = 0
    parsed_files = 0
    skipped_files = 0
    date_filtered = 0
    
    # Calculate cutoff date (timezone-aware)
    from datetime import timezone
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    
    print(f"Starting to parse CVE files from: {data_dir}")
    print(f"Filtering to CVEs published after: {cutoff_date.strftime('%Y-%m-%d')}")
    
    if not os.path.exists(data_dir):
        print(f"ERROR: Directory {data_dir} does not exist!")
        return associations
    
    for root, dirs, files in os.walk(data_dir):
        for filename in files:
            if not filename.startswith("CVE-") or not filename.endswith(".json"):
                continue
                
            total_files += 1
            filepath = os.path.join(root, filename)
            
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)
                
                # Check publication date
                cve_metadata = cve_data.get("cveMetadata", {})
                date_published = cve_metadata.get("datePublished")
                
                if date_published:
                    try:
                        # Parse ISO 8601 datetime
                        pub_date = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
                        if pub_date < cutoff_date:
                            date_filtered += 1
                            continue
                    except (ValueError, AttributeError):
                        # If date parsing fails, include the CVE
                        pass
                
                # Extract CNA (assignerOrgId and human-readable name)
                cna_uuid = cve_metadata.get("assignerOrgId")
                cna_short_name = cve_metadata.get("assignerShortName")
                
                if not cna_uuid:
                    skipped_files += 1
                    continue
                
                # Store the human-readable name (prefer shortName, fallback to UUID)
                if cna_short_name and cna_uuid not in cna_names:
                    cna_names[cna_uuid] = cna_short_name
                elif cna_uuid not in cna_names:
                    cna_names[cna_uuid] = cna_uuid
                
                # Use the UUID as the key (we'll map it to name later)
                cna = cna_uuid
                
                # Extract CWEs from problemTypes
                containers = cve_data.get("containers", {})
                cwes_found = set()
                
                # Check CNA container (primary source)
                cna_container = containers.get("cna", {})
                problem_types = cna_container.get("problemTypes", [])
                for problem_type in problem_types:
                    descriptions = problem_type.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("type") == "CWE":
                            # Try both 'cweId' (modern format) and 'value' (legacy format)
                            cwe_value = desc.get("cweId") or desc.get("value")
                            if cwe_value and cwe_value.startswith("CWE-"):
                                cwes_found.add(cwe_value)
                
                # Check ADP containers (Authorized Data Publishers - additional enrichment)
                adp_containers = containers.get("adp", [])
                if isinstance(adp_containers, list):
                    for adp in adp_containers:
                        adp_problem_types = adp.get("problemTypes", [])
                        for problem_type in adp_problem_types:
                            descriptions = problem_type.get("descriptions", [])
                            for desc in descriptions:
                                if desc.get("type") == "CWE":
                                    # ADP also uses cweId
                                    cwe_value = desc.get("cweId") or desc.get("value")
                                    if cwe_value and cwe_value.startswith("CWE-"):
                                        cwes_found.add(cwe_value)
                
                # Record associations
                for cwe in cwes_found:
                    associations[(cna, cwe)] += 1
                
                if cwes_found:
                    parsed_files += 1
                    
            except json.JSONDecodeError:
                print(f"WARNING: Skipping malformed JSON: {filepath}")
                skipped_files += 1
            except KeyError as e:
                print(f"WARNING: Missing key in {filepath}: {e}")
                skipped_files += 1
            except Exception as e:
                print(f"WARNING: Error processing {filepath}: {e}")
                skipped_files += 1
            
            # Progress indicator
            if total_files % 10000 == 0:
                print(f"Processed {total_files} files...")
    
    print(f"\nParsing complete!")
    print(f"Total CVE files found: {total_files}")
    print(f"Files filtered by date: {date_filtered}")
    print(f"Files with CNA-CWE associations: {parsed_files}")
    print(f"Files skipped: {skipped_files}")
    print(f"Unique CNA-CWE associations: {len(associations)}")
    print(f"Unique CNAs identified: {len(cna_names)}")
    
    return associations, cna_names


def build_graph(associations, cna_names):
    """
    Build a NetworkX graph from CNA-CWE associations.
    
    Args:
        associations: dict of (cna_uuid, cwe) -> count
        cna_names: dict mapping UUID to human-readable name
        
    Returns:
        networkx.Graph: Graph with CNAs and CWEs as nodes, weighted edges
    """
    G = nx.Graph()
    
    # Collect all unique CNAs and CWEs
    cnas = set()
    cwes = set()
    
    for (cna_uuid, cwe), count in associations.items():
        cnas.add(cna_uuid)
        cwes.add(cwe)
    
    # Add CNA nodes with human-readable names
    for cna_uuid in cnas:
        cna_name = cna_names.get(cna_uuid, cna_uuid)
        G.add_node(cna_name, type='cna', label=cna_name, uuid=cna_uuid)
    
    # Add CWE nodes
    for cwe in cwes:
        G.add_node(cwe, type='cwe', label=cwe)
    
    # Add edges with weights (map UUID to name)
    for (cna_uuid, cwe), count in associations.items():
        cna_name = cna_names.get(cna_uuid, cna_uuid)
        G.add_edge(cna_name, cwe, weight=count)
    
    print(f"\nGraph built successfully!")
    print(f"CNA nodes: {len(cnas)}")
    print(f"CWE nodes: {len(cwes)}")
    print(f"Edges: {G.number_of_edges()}")
    
    return G


def export_graph(graph, output_path="web/data/cna_to_cwe_map.json"):
    """
    Export graph to JSON format for web visualization.
    
    Args:
        graph: NetworkX graph
        output_path: Path to save JSON file
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Convert graph to node-link format
    graph_data = nx.readwrite.json_graph.node_link_data(graph)
    
    # Add metadata
    graph_data['metadata'] = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'node_count': graph.number_of_nodes(),
        'edge_count': graph.number_of_edges(),
        'cna_count': len([n for n, d in graph.nodes(data=True) if d.get('type') == 'cna']),
        'cwe_count': len([n for n, d in graph.nodes(data=True) if d.get('type') == 'cwe'])
    }
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(graph_data, f, indent=2)
    
    print(f"\nGraph exported to: {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024:.2f} KB")
    
    # Also create a last_updated timestamp file
    timestamp_path = os.path.join(os.path.dirname(output_path), "last_updated.txt")
    with open(timestamp_path, 'w') as f:
        f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    
    print(f"Timestamp saved to: {timestamp_path}")


def main():
    """Main execution function."""
    print("=" * 60)
    print("CVE Map Builder - CNA to CWE Association Graph")
    print("=" * 60)
    
    # Parse CVE files
    associations, cna_names = parse_cve_files("cve-data/cves")
    
    if not associations:
        print("\nERROR: No associations found. Please check the data directory.")
        return
    
    # Build graph
    graph = build_graph(associations, cna_names)
    
    # Export graph
    export_graph(graph, "web/data/cna_to_cwe_map.json")
    
    print("\n" + "=" * 60)
    print("Build complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()

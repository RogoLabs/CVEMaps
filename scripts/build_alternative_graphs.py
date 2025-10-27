#!/usr/bin/env python3
"""
Alternative CVE Graph Builders
Generates various graph visualizations from CVE data beyond the basic CNA-CWE map.
"""

import os
import json
import networkx as nx
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from itertools import combinations


def parse_cve_files_extended(data_dir="cve-data/cves", days_back=365):
    """
    Parse CVE files and extract comprehensive data for multiple graph types.
    
    Returns:
        dict: Contains multiple data structures for different graph types
    """
    data = {
        'cve_to_cwes': defaultdict(set),           # CVE -> {CWE1, CWE2, ...}
        'cve_to_products': defaultdict(set),        # CVE -> {(vendor, product), ...}
        'cve_to_vendors': defaultdict(set),         # CVE -> {vendor1, vendor2, ...}
        'cve_to_cna': {},                          # CVE -> CNA
        'cve_to_references': defaultdict(set),      # CVE -> {url1, url2, ...}
        'cve_metadata': {},                        # CVE -> {published, modified, etc}
    }
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    total_files = 0
    parsed_files = 0
    
    print(f"Parsing CVE files from: {data_dir}")
    print(f"Date filter: After {cutoff_date.strftime('%Y-%m-%d')}")
    
    for root, dirs, files in os.walk(data_dir):
        for filename in files:
            if not filename.startswith("CVE-") or not filename.endswith(".json"):
                continue
            
            total_files += 1
            filepath = os.path.join(root, filename)
            
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)
                
                cve_metadata = cve_data.get("cveMetadata", {})
                cve_id = cve_metadata.get("cveId")
                
                if not cve_id:
                    continue
                
                # Date filter
                date_published = cve_metadata.get("datePublished")
                if date_published:
                    try:
                        pub_date = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
                        if pub_date < cutoff_date:
                            continue
                    except (ValueError, AttributeError):
                        pass
                
                # Extract CNA
                cna = cve_metadata.get("assignerShortName") or cve_metadata.get("assignerOrgId")
                if cna:
                    data['cve_to_cna'][cve_id] = cna
                
                # Store metadata
                data['cve_metadata'][cve_id] = {
                    'published': date_published,
                    'modified': cve_metadata.get("dateUpdated"),
                    'state': cve_metadata.get("state")
                }
                
                containers = cve_data.get("containers", {})
                
                # Extract CWEs
                cna_container = containers.get("cna", {})
                problem_types = cna_container.get("problemTypes", [])
                for problem_type in problem_types:
                    for desc in problem_type.get("descriptions", []):
                        if desc.get("type") == "CWE":
                            cwe_value = desc.get("cweId") or desc.get("value")
                            if cwe_value and cwe_value.startswith("CWE-"):
                                data['cve_to_cwes'][cve_id].add(cwe_value)
                
                # Check ADP for CWEs
                adp_containers = containers.get("adp", [])
                if isinstance(adp_containers, list):
                    for adp in adp_containers:
                        for problem_type in adp.get("problemTypes", []):
                            for desc in problem_type.get("descriptions", []):
                                if desc.get("type") == "CWE":
                                    cwe_value = desc.get("cweId") or desc.get("value")
                                    if cwe_value and cwe_value.startswith("CWE-"):
                                        data['cve_to_cwes'][cve_id].add(cwe_value)
                
                # Extract affected products and vendors
                affected = cna_container.get("affected", [])
                for item in affected:
                    vendor = item.get("vendor", "").strip()
                    product = item.get("product", "").strip()
                    
                    if vendor:
                        data['cve_to_vendors'][cve_id].add(vendor)
                    
                    if vendor and product:
                        data['cve_to_products'][cve_id].add((vendor, product))
                
                # Extract references
                references = cna_container.get("references", [])
                for ref in references:
                    url = ref.get("url", "").strip()
                    if url:
                        data['cve_to_references'][cve_id].add(url)
                
                parsed_files += 1
                
            except Exception as e:
                pass
            
            if total_files % 10000 == 0:
                print(f"Processed {total_files} files...")
    
    print(f"\nParsing complete!")
    print(f"Total files: {total_files}")
    print(f"Parsed CVEs: {parsed_files}")
    
    return data


def build_cwe_cooccurrence_graph(data):
    """
    Build CWE Co-occurrence Map (CWE <-> CWE).
    Connects CWEs that appear together in the same CVE.
    """
    print("\n" + "="*60)
    print("Building CWE Co-occurrence Graph")
    print("="*60)
    
    G = nx.Graph()
    edge_weights = defaultdict(int)
    
    # Find all CWE pairs that co-occur
    for cve_id, cwes in data['cve_to_cwes'].items():
        if len(cwes) > 1:
            # Create edges between all pairs of CWEs in this CVE
            for cwe1, cwe2 in combinations(sorted(cwes), 2):
                edge_weights[(cwe1, cwe2)] += 1
    
    # Add nodes and edges
    all_cwes = set()
    for cwes in data['cve_to_cwes'].values():
        all_cwes.update(cwes)
    
    for cwe in all_cwes:
        G.add_node(cwe, type='cwe', label=cwe)
    
    for (cwe1, cwe2), weight in edge_weights.items():
        G.add_edge(cwe1, cwe2, weight=weight)
    
    print(f"CWE nodes: {G.number_of_nodes()}")
    print(f"Co-occurrence edges: {G.number_of_edges()}")
    
    return G


def build_product_cwe_graph(data):
    """
    Build Product Vulnerability Profile (Product <-> CWE).
    Links products to the CWEs that affect them.
    """
    print("\n" + "="*60)
    print("Building Product-CWE Graph")
    print("="*60)
    
    G = nx.Graph()
    product_cwe_weights = defaultdict(int)
    
    # Connect products to CWEs
    for cve_id, products in data['cve_to_products'].items():
        cwes = data['cve_to_cwes'].get(cve_id, set())
        for vendor, product in products:
            product_key = f"{vendor}::{product}"
            for cwe in cwes:
                product_cwe_weights[(product_key, cwe)] += 1
    
    # Add nodes
    products = set()
    cwes = set()
    for (prod, cwe), weight in product_cwe_weights.items():
        products.add(prod)
        cwes.add(cwe)
    
    for prod in products:
        vendor, product = prod.split("::", 1)
        G.add_node(prod, type='product', label=product, vendor=vendor)
    
    for cwe in cwes:
        G.add_node(cwe, type='cwe', label=cwe)
    
    # Add edges
    for (prod, cwe), weight in product_cwe_weights.items():
        G.add_edge(prod, cwe, weight=weight)
    
    print(f"Product nodes: {len(products)}")
    print(f"CWE nodes: {len(cwes)}")
    print(f"Edges: {G.number_of_edges()}")
    
    return G


def build_vendor_cwe_graph(data):
    """
    Build Vendor Vulnerability Profile (Vendor <-> CWE).
    Links vendors to the CWEs that affect their products.
    """
    print("\n" + "="*60)
    print("Building Vendor-CWE Graph")
    print("="*60)
    
    G = nx.Graph()
    vendor_cwe_weights = defaultdict(int)
    
    # Connect vendors to CWEs
    for cve_id, vendors in data['cve_to_vendors'].items():
        cwes = data['cve_to_cwes'].get(cve_id, set())
        for vendor in vendors:
            for cwe in cwes:
                vendor_cwe_weights[(vendor, cwe)] += 1
    
    # Add nodes
    vendors = set()
    cwes = set()
    for (vendor, cwe), weight in vendor_cwe_weights.items():
        vendors.add(vendor)
        cwes.add(cwe)
    
    for vendor in vendors:
        G.add_node(vendor, type='vendor', label=vendor)
    
    for cwe in cwes:
        G.add_node(cwe, type='cwe', label=cwe)
    
    # Add edges
    for (vendor, cwe), weight in vendor_cwe_weights.items():
        G.add_edge(vendor, cwe, weight=weight)
    
    print(f"Vendor nodes: {len(vendors)}")
    print(f"CWE nodes: {len(cwes)}")
    print(f"Edges: {G.number_of_edges()}")
    
    return G


def build_cve_temporal_graph(data, days_window=30):
    """
    Build Vulnerability Chaining Map (CVE <-> CVE).
    Links CVEs affecting the same product within a time window.
    """
    print("\n" + "="*60)
    print(f"Building CVE Temporal Chaining Graph ({days_window} day window)")
    print("="*60)
    
    G = nx.Graph()
    
    # Group CVEs by product
    product_cves = defaultdict(list)
    for cve_id, products in data['cve_to_products'].items():
        pub_date_str = data['cve_metadata'].get(cve_id, {}).get('published')
        if not pub_date_str:
            continue
        
        try:
            pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
        except:
            continue
        
        for vendor, product in products:
            product_key = f"{vendor}::{product}"
            product_cves[product_key].append((cve_id, pub_date))
    
    # Find CVE pairs within time window
    edge_count = 0
    for product_key, cve_list in product_cves.items():
        # Sort by date
        cve_list.sort(key=lambda x: x[1])
        
        # Find pairs within window
        for i, (cve1, date1) in enumerate(cve_list):
            for cve2, date2 in cve_list[i+1:]:
                if (date2 - date1).days <= days_window:
                    G.add_edge(cve1, cve2, 
                              product=product_key,
                              days_apart=(date2 - date1).days)
                    edge_count += 1
                else:
                    break  # No need to check further
    
    # Add node attributes
    for node in G.nodes():
        G.nodes[node]['type'] = 'cve'
        G.nodes[node]['label'] = node
        cna = data['cve_to_cna'].get(node)
        if cna:
            G.nodes[node]['cna'] = cna
    
    print(f"CVE nodes: {G.number_of_nodes()}")
    print(f"Temporal links: {G.number_of_edges()}")
    
    return G


def build_shared_reference_graph(data, min_shared=2):
    """
    Build Shared Reference Map (CVE <-> CVE).
    Links CVEs that share reference URLs.
    """
    print("\n" + "="*60)
    print(f"Building Shared Reference Graph (min {min_shared} shared refs)")
    print("="*60)
    
    G = nx.Graph()
    
    # Group CVEs by reference URL
    url_to_cves = defaultdict(set)
    for cve_id, urls in data['cve_to_references'].items():
        for url in urls:
            url_to_cves[url].add(cve_id)
    
    # Create edges between CVEs sharing references
    cve_pairs = defaultdict(set)  # Track which URLs link each pair
    for url, cves in url_to_cves.items():
        if len(cves) > 1:
            for cve1, cve2 in combinations(sorted(cves), 2):
                cve_pairs[(cve1, cve2)].add(url)
    
    # Add edges only if pairs share enough references
    for (cve1, cve2), shared_urls in cve_pairs.items():
        if len(shared_urls) >= min_shared:
            G.add_edge(cve1, cve2, 
                      weight=len(shared_urls),
                      shared_refs=len(shared_urls))
    
    # Add node attributes
    for node in G.nodes():
        G.nodes[node]['type'] = 'cve'
        G.nodes[node]['label'] = node
        cna = data['cve_to_cna'].get(node)
        if cna:
            G.nodes[node]['cna'] = cna
    
    print(f"CVE nodes: {G.number_of_nodes()}")
    print(f"Shared reference links: {G.number_of_edges()}")
    
    return G


def build_product_dependency_graph(data):
    """
    Build Product Dependency Map (Product <-> Product).
    Links products affected by the same CVE.
    """
    print("\n" + "="*60)
    print("Building Product Dependency Graph")
    print("="*60)
    
    G = nx.Graph()
    edge_weights = defaultdict(int)
    
    # Find product pairs that share CVEs
    for cve_id, products in data['cve_to_products'].items():
        if len(products) > 1:
            for (v1, p1), (v2, p2) in combinations(sorted(products), 2):
                prod1 = f"{v1}::{p1}"
                prod2 = f"{v2}::{p2}"
                edge_weights[(prod1, prod2)] += 1
    
    # Add nodes
    all_products = set()
    for products in data['cve_to_products'].values():
        for vendor, product in products:
            all_products.add(f"{vendor}::{product}")
    
    for prod in all_products:
        vendor, product = prod.split("::", 1)
        G.add_node(prod, type='product', label=product, vendor=vendor)
    
    # Add edges
    for (prod1, prod2), weight in edge_weights.items():
        G.add_edge(prod1, prod2, weight=weight)
    
    print(f"Product nodes: {G.number_of_nodes()}")
    print(f"Dependency edges: {G.number_of_edges()}")
    
    return G


def build_cna_vendor_graph(data):
    """
    Build CNA-Vendor Reporting Map (CNA <-> Vendor).
    Links CNAs to vendors they report on.
    """
    print("\n" + "="*60)
    print("Building CNA-Vendor Reporting Graph")
    print("="*60)
    
    G = nx.Graph()
    cna_vendor_weights = defaultdict(int)
    
    # Connect CNAs to vendors
    for cve_id, cna in data['cve_to_cna'].items():
        vendors = data['cve_to_vendors'].get(cve_id, set())
        for vendor in vendors:
            cna_vendor_weights[(cna, vendor)] += 1
    
    # Add nodes
    cnas = set()
    vendors = set()
    for (cna, vendor), weight in cna_vendor_weights.items():
        cnas.add(cna)
        vendors.add(vendor)
    
    for cna in cnas:
        G.add_node(cna, type='cna', label=cna)
    
    for vendor in vendors:
        G.add_node(vendor, type='vendor', label=vendor)
    
    # Add edges
    for (cna, vendor), weight in cna_vendor_weights.items():
        G.add_edge(cna, vendor, weight=weight)
    
    print(f"CNA nodes: {len(cnas)}")
    print(f"Vendor nodes: {len(vendors)}")
    print(f"Edges: {G.number_of_edges()}")
    
    return G


def export_graph(graph, filename, graph_type):
    """Export graph to JSON format."""
    output_path = f"web/data/{filename}"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    graph_data = nx.readwrite.json_graph.node_link_data(graph)
    graph_data['metadata'] = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'type': graph_type,
        'node_count': graph.number_of_nodes(),
        'edge_count': graph.number_of_edges()
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(graph_data, f, indent=2)
    
    print(f"Exported to: {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024:.2f} KB")


def main():
    """Main execution."""
    print("="*60)
    print("Alternative CVE Graph Builder")
    print("="*60)
    
    # Parse data
    data = parse_cve_files_extended("cve-data/cves", days_back=365)
    
    # Build all graphs
    graphs = {
        'cwe_cooccurrence': ('CWE Co-occurrence', build_cwe_cooccurrence_graph(data)),
        'product_cwe': ('Product-CWE', build_product_cwe_graph(data)),
        'vendor_cwe': ('Vendor-CWE', build_vendor_cwe_graph(data)),
        'cve_temporal': ('CVE Temporal Chaining', build_cve_temporal_graph(data, days_window=30)),
        'cve_references': ('Shared References', build_shared_reference_graph(data, min_shared=2)),
        'product_dependency': ('Product Dependency', build_product_dependency_graph(data)),
        'cna_vendor': ('CNA-Vendor', build_cna_vendor_graph(data)),
    }
    
    # Export all graphs
    print("\n" + "="*60)
    print("Exporting Graphs")
    print("="*60)
    
    for key, (name, graph) in graphs.items():
        print(f"\nExporting {name}...")
        export_graph(graph, f"{key}_map.json", name)
    
    print("\n" + "="*60)
    print("All graphs built successfully!")
    print("="*60)


if __name__ == "__main__":
    main()

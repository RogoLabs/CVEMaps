#!/usr/bin/env python3
"""
Compact CVE Graph Builders
Creates smaller, more focused visualizations using NetworkX's advanced features.
"""

import os
import json
import networkx as nx
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
import math


def parse_cve_files_compact(data_dir="cve-data/cves", days_back=365):
    """Parse CVE files for compact graph generation."""
    data = {
        'cve_to_cwes': defaultdict(set),
        'cve_to_cna': {},
        'cwe_to_cves': defaultdict(set),
        'cna_to_cves': defaultdict(set),
    }
    
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    total_files = 0
    
    print(f"Parsing CVE files from: {data_dir}")
    
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
                    except:
                        pass
                
                # Extract CNA
                cna = cve_metadata.get("assignerShortName") or cve_metadata.get("assignerOrgId")
                if cna:
                    data['cve_to_cna'][cve_id] = cna
                    data['cna_to_cves'][cna].add(cve_id)
                
                # Extract CWEs
                containers = cve_data.get("containers", {})
                cna_container = containers.get("cna", {})
                problem_types = cna_container.get("problemTypes", [])
                
                for problem_type in problem_types:
                    for desc in problem_type.get("descriptions", []):
                        if desc.get("type") == "CWE":
                            cwe_value = desc.get("cweId") or desc.get("value")
                            if cwe_value and cwe_value.startswith("CWE-"):
                                data['cve_to_cwes'][cve_id].add(cwe_value)
                                data['cwe_to_cves'][cwe_value].add(cve_id)
                
                # Check ADP
                adp_containers = containers.get("adp", [])
                if isinstance(adp_containers, list):
                    for adp in adp_containers:
                        for problem_type in adp.get("problemTypes", []):
                            for desc in problem_type.get("descriptions", []):
                                if desc.get("type") == "CWE":
                                    cwe_value = desc.get("cweId") or desc.get("value")
                                    if cwe_value and cwe_value.startswith("CWE-"):
                                        data['cve_to_cwes'][cve_id].add(cwe_value)
                                        data['cwe_to_cves'][cwe_value].add(cve_id)
                
            except:
                pass
            
            if total_files % 10000 == 0:
                print(f"Processed {total_files} files...")
    
    print(f"Parsing complete! Processed {total_files} files")
    return data


def build_top_cna_cwe_bipartite(data, top_n=50):
    """
    Bipartite graph of top N CNAs and their CWEs.
    Uses NetworkX bipartite layout.
    """
    print("\n" + "="*60)
    print(f"Building Top {top_n} CNA-CWE Bipartite Graph")
    print("="*60)
    
    # Get top CNAs by CVE count
    cna_counts = {cna: len(cves) for cna, cves in data['cna_to_cves'].items()}
    top_cnas = sorted(cna_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    top_cna_names = [cna for cna, _ in top_cnas]
    
    # Build bipartite graph
    G = nx.Graph()
    
    # Add CNA nodes (set 0)
    for cna, count in top_cnas:
        G.add_node(cna, bipartite=0, type='cna', label=cna, cve_count=count)
    
    # Count CWEs for these CNAs
    cwe_counts = defaultdict(int)
    for cna in top_cna_names:
        for cve_id in data['cna_to_cves'][cna]:
            for cwe in data['cve_to_cwes'].get(cve_id, set()):
                cwe_counts[(cna, cwe)] += 1
    
    # Add CWE nodes (set 1) and edges
    cwes_added = set()
    for (cna, cwe), count in cwe_counts.items():
        if cwe not in cwes_added:
            G.add_node(cwe, bipartite=1, type='cwe', label=cwe)
            cwes_added.add(cwe)
        G.add_edge(cna, cwe, weight=count)
    
    print(f"CNA nodes: {len(top_cna_names)}")
    print(f"CWE nodes: {len(cwes_added)}")
    print(f"Edges: {G.number_of_edges()}")
    
    return G


def build_cwe_hierarchy_tree(data, top_n=30):
    """
    Tree/hierarchical view grouping CWEs by their category (first digit).
    Uses NetworkX tree layout.
    """
    print("\n" + "="*60)
    print(f"Building CWE Hierarchy Tree (Top {top_n})")
    print("="*60)
    
    # Get top CWEs by CVE count
    cwe_counts = {cwe: len(cves) for cwe, cves in data['cwe_to_cves'].items()}
    top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    # Group by category (CWE-XXX -> category XXX/100)
    categories = defaultdict(list)
    for cwe, count in top_cwes:
        try:
            cwe_num = int(cwe.split('-')[1])
            category = (cwe_num // 100) * 100
            categories[category].append((cwe, count))
        except:
            categories[0].append((cwe, count))
    
    # Build tree
    G = nx.DiGraph()
    
    # Add root
    G.add_node("root", type='root', label="All CWEs", level=0)
    
    # Add category nodes
    for cat_num, cwes in categories.items():
        cat_name = f"CWE-{cat_num}xx"
        total_count = sum(count for _, count in cwes)
        G.add_node(cat_name, type='category', label=cat_name, level=1, count=total_count)
        G.add_edge("root", cat_name, weight=total_count)
        
        # Add individual CWEs
        for cwe, count in cwes:
            G.add_node(cwe, type='cwe', label=cwe, level=2, count=count)
            G.add_edge(cat_name, cwe, weight=count)
    
    print(f"Categories: {len(categories)}")
    print(f"CWEs: {len(top_cwes)}")
    print(f"Total nodes: {G.number_of_nodes()}")
    
    return G


def build_cwe_star_graphs(data, top_n=10):
    """
    Multiple star graphs showing individual CWEs and their CNAs.
    Each CWE is a center with CNAs as spokes.
    """
    print("\n" + "="*60)
    print(f"Building Top {top_n} CWE Star Graphs")
    print("="*60)
    
    # Get top CWEs
    cwe_counts = {cwe: len(cves) for cwe, cves in data['cwe_to_cves'].items()}
    top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    # Build combined graph with all stars
    G = nx.Graph()
    
    for cwe, cve_count in top_cwes:
        # Add center CWE node with unique position marker
        G.add_node(cwe, type='cwe', label=cwe, role='center', cve_count=cve_count)
        
        # Find CNAs that reported this CWE
        cna_counts = defaultdict(int)
        for cve_id in data['cwe_to_cves'][cwe]:
            cna = data['cve_to_cna'].get(cve_id)
            if cna:
                cna_counts[cna] += 1
        
        # Add CNA nodes and edges (limit to top CNAs for this CWE)
        for cna, count in sorted(cna_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            node_id = f"{cwe}_{cna}"  # Unique node per star
            G.add_node(node_id, type='cna', label=cna, role='spoke', parent=cwe)
            G.add_edge(cwe, node_id, weight=count)
    
    print(f"Stars: {len(top_cwes)}")
    print(f"Total nodes: {G.number_of_nodes()}")
    print(f"Total edges: {G.number_of_edges()}")
    
    return G


def build_cna_ego_network(data, cna_name="mitre", radius=2):
    """
    Ego network centered on a specific CNA.
    Shows the CNA, its CWEs, and other CNAs that share those CWEs.
    """
    print("\n" + "="*60)
    print(f"Building Ego Network for CNA: {cna_name}")
    print("="*60)
    
    # Build full CNA-CWE graph first
    full_graph = nx.Graph()
    
    for cve_id, cna in data['cve_to_cna'].items():
        cwes = data['cve_to_cwes'].get(cve_id, set())
        for cwe in cwes:
            if full_graph.has_edge(cna, cwe):
                full_graph[cna][cwe]['weight'] += 1
            else:
                full_graph.add_edge(cna, cwe, weight=1)
    
    # Add node types
    for node in full_graph.nodes():
        if node.startswith("CWE-"):
            full_graph.nodes[node]['type'] = 'cwe'
            full_graph.nodes[node]['label'] = node
        else:
            full_graph.nodes[node]['type'] = 'cna'
            full_graph.nodes[node]['label'] = node
    
    # Extract ego network
    if cna_name in full_graph:
        G = nx.ego_graph(full_graph, cna_name, radius=radius)
        print(f"Ego network nodes: {G.number_of_nodes()}")
        print(f"Ego network edges: {G.number_of_edges()}")
        return G
    else:
        print(f"CNA '{cna_name}' not found!")
        return nx.Graph()


def build_circular_cwe_layout(data, top_n=50):
    """
    Circular layout with top CWEs arranged in a circle.
    Connections show co-occurrence.
    """
    print("\n" + "="*60)
    print(f"Building Circular CWE Layout (Top {top_n})")
    print("="*60)
    
    # Get top CWEs
    cwe_counts = {cwe: len(cves) for cwe, cves in data['cwe_to_cves'].items()}
    top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    top_cwe_ids = [cwe for cwe, _ in top_cwes]
    
    # Build co-occurrence graph
    G = nx.Graph()
    
    # Add nodes
    for cwe, count in top_cwes:
        G.add_node(cwe, type='cwe', label=cwe, cve_count=count)
    
    # Add edges for co-occurrence
    edge_weights = defaultdict(int)
    for cve_id, cwes in data['cve_to_cwes'].items():
        cwes_in_top = [c for c in cwes if c in top_cwe_ids]
        if len(cwes_in_top) > 1:
            for i, cwe1 in enumerate(cwes_in_top):
                for cwe2 in cwes_in_top[i+1:]:
                    edge_weights[(cwe1, cwe2)] += 1
    
    # Add edges
    for (cwe1, cwe2), weight in edge_weights.items():
        G.add_edge(cwe1, cwe2, weight=weight)
    
    print(f"CWE nodes: {G.number_of_nodes()}")
    print(f"Co-occurrence edges: {G.number_of_edges()}")
    
    return G


def build_cna_collaboration_network(data, min_shared_cwes=5):
    """
    Network showing CNAs that 'collaborate' by reporting the same CWEs.
    Edge weight = number of shared CWEs.
    """
    print("\n" + "="*60)
    print(f"Building CNA Collaboration Network (min {min_shared_cwes} shared CWEs)")
    print("="*60)
    
    # Find CWEs for each CNA
    cna_cwes = {}
    for cna, cve_ids in data['cna_to_cves'].items():
        cwes = set()
        for cve_id in cve_ids:
            cwes.update(data['cve_to_cwes'].get(cve_id, set()))
        cna_cwes[cna] = cwes
    
    # Build collaboration network
    G = nx.Graph()
    
    # Add all CNAs
    for cna, cwes in cna_cwes.items():
        G.add_node(cna, type='cna', label=cna, cwe_count=len(cwes))
    
    # Add edges for shared CWEs
    cnas = list(cna_cwes.keys())
    for i, cna1 in enumerate(cnas):
        for cna2 in cnas[i+1:]:
            shared = cna_cwes[cna1] & cna_cwes[cna2]
            if len(shared) >= min_shared_cwes:
                G.add_edge(cna1, cna2, weight=len(shared), shared_count=len(shared))
    
    print(f"CNA nodes: {G.number_of_nodes()}")
    print(f"Collaboration edges: {G.number_of_edges()}")
    
    return G


def export_graph_with_layout(graph, filename, graph_type, layout_type="force"):
    """
    Export graph with pre-computed layout positions.
    """
    output_path = f"web/data/{filename}"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Compute layout based on type
    if layout_type == "bipartite" and nx.is_bipartite(graph):
        # Manual bipartite layout without numpy
        top_nodes = [n for n, d in graph.nodes(data=True) if d.get('bipartite') == 0]
        bottom_nodes = [n for n, d in graph.nodes(data=True) if d.get('bipartite') == 1]
        
        pos = {}
        # Top nodes (CNAs) on left
        for i, node in enumerate(top_nodes):
            pos[node] = (-400, i * (1000 / max(len(top_nodes), 1)) - 500)
        # Bottom nodes (CWEs) on right
        for i, node in enumerate(bottom_nodes):
            pos[node] = (400, i * (1000 / max(len(bottom_nodes), 1)) - 500)
    elif layout_type == "circular":
        pos = nx.circular_layout(graph, scale=1000)
    elif layout_type == "tree" and isinstance(graph, nx.DiGraph):
        # Simple tree layout without graphviz
        pos = nx.spring_layout(graph, k=2, iterations=50, scale=1000)
    elif layout_type == "spring":
        pos = nx.spring_layout(graph, k=1.5, iterations=50, scale=1000)
    else:
        # Default force-directed
        pos = nx.spring_layout(graph, k=2, iterations=50, scale=1000)
    
    # Add positions to nodes
    for node, (x, y) in pos.items():
        graph.nodes[node]['x'] = float(x)
        graph.nodes[node]['y'] = float(y)
    
    # Convert to JSON
    graph_data = nx.readwrite.json_graph.node_link_data(graph)
    graph_data['metadata'] = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'type': graph_type,
        'layout': layout_type,
        'node_count': graph.number_of_nodes(),
        'edge_count': graph.number_of_edges()
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(graph_data, f, indent=2)
    
    file_size = os.path.getsize(output_path) / 1024
    print(f"Exported to: {output_path}")
    print(f"File size: {file_size:.2f} KB")
    
    return file_size


def main():
    """Main execution."""
    print("="*60)
    print("Compact CVE Graph Builder")
    print("="*60)
    
    # Parse data
    data = parse_cve_files_compact("cve-data/cves", days_back=365)
    
    # Build graphs
    graphs = []
    
    # 1. Top 50 CNAs Bipartite
    g = build_top_cna_cwe_bipartite(data, top_n=50)
    size = export_graph_with_layout(g, "top_cna_cwe_bipartite.json", "Top CNA-CWE Bipartite", "bipartite")
    graphs.append(("Top 50 CNA-CWE Bipartite", size, "✅" if size < 1000 else "⚠️"))
    
    # 2. CWE Hierarchy Tree
    g = build_cwe_hierarchy_tree(data, top_n=40)
    size = export_graph_with_layout(g, "cwe_hierarchy_tree.json", "CWE Hierarchy Tree", "tree")
    graphs.append(("CWE Hierarchy Tree", size, "✅" if size < 1000 else "⚠️"))
    
    # 3. CWE Star Graphs
    g = build_cwe_star_graphs(data, top_n=12)
    size = export_graph_with_layout(g, "cwe_star_graphs.json", "CWE Star Graphs", "spring")
    graphs.append(("Top 12 CWE Stars", size, "✅" if size < 1000 else "⚠️"))
    
    # 4. Circular CWE Layout
    g = build_circular_cwe_layout(data, top_n=40)
    size = export_graph_with_layout(g, "cwe_circular_layout.json", "Circular CWE Layout", "circular")
    graphs.append(("Circular CWE (Top 40)", size, "✅" if size < 1000 else "⚠️"))
    
    # 5. CNA Collaboration Network
    g = build_cna_collaboration_network(data, min_shared_cwes=10)
    size = export_graph_with_layout(g, "cna_collaboration.json", "CNA Collaboration Network", "spring")
    graphs.append(("CNA Collaboration", size, "✅" if size < 1000 else "⚠️"))
    
    # 6. MITRE Ego Network (smaller radius to keep it manageable)
    g = build_cna_ego_network(data, cna_name="mitre", radius=1)
    if g.number_of_nodes() > 0 and g.number_of_nodes() < 500:
        size = export_graph_with_layout(g, "mitre_ego_network.json", "MITRE Ego Network", "spring")
        graphs.append(("MITRE Ego Network", size, "✅" if size < 1000 else "⚠️"))
    elif g.number_of_nodes() >= 500:
        print(f"⚠️  MITRE ego network too large ({g.number_of_nodes()} nodes), skipping...")
        graphs.append(("MITRE Ego Network", 0, "⚠️ Too large, skipped"))
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY - Generated Graphs")
    print("="*60)
    for name, size, status in graphs:
        print(f"{status} {name:40s} {size:8.2f} KB")
    
    print("\n" + "="*60)
    print("All compact graphs built successfully!")
    print("="*60)


if __name__ == "__main__":
    main()

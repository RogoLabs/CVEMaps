## Alternative Graph Visualizations for CVE Data

This document describes various graph types that can be generated from CVE data beyond the basic CNA-CWE mapping.

---

## Original Suggested Visualizations

## 1. **Hierarchical/Tree Visualization** ⭐ RECOMMENDED
**Why it's better:** Shows clear parent-child relationships and makes it easier to see CWE categories.

**Benefits:**
- CNAs at the top level
- CWEs grouped by category (e.g., CWE-79 variants together)
- Clear hierarchy with collapsible nodes
- Better for exploring specific CNA activity

**Implementation:**
- Use D3.js tree or cluster layout
- Group CWEs by their first digit (CWE-7xx, CWE-8xx, etc.)
- Allow collapsing/expanding branches

## 2. **Sankey Diagram** ⭐ RECOMMENDED
**Why it's better:** Shows flow and weight of associations visually with thickness.

**Benefits:**
- CNAs on the left, CWEs on the right
- Flow width shows association strength
- Easy to see which CNAs contribute most to specific CWEs
- Great for presentations and reports

**Implementation:**
- Use D3-sankey or Plotly
- Left nodes: CNAs
- Right nodes: CWEs
- Flow thickness: number of CVEs

## 3. **Chord Diagram**
**Why it's interesting:** Shows circular relationships and helps identify clusters.

**Benefits:**
- Compact circular layout
- Good for seeing mutual relationships
- Aesthetically pleasing
- Shows connection density

**Implementation:**
- Use D3.js chord layout
- Arrange CNAs and CWEs around a circle
- Curved links show associations

## 4. **Heatmap Matrix** ⭐ RECOMMENDED FOR ANALYSIS
**Why it's better:** Easy to spot patterns and hotspots.

**Benefits:**
- CNAs on Y-axis, CWEs on X-axis
- Cell color intensity = number of CVEs
- Sortable and filterable
- Exportable to CSV
- Great for finding trends

**Implementation:**
- Use Plotly heatmap or D3.js
- Interactive zoom and filter
- Click cells to see CVE list

## 5. **Bipartite Graph with Better Layout**
**Why it's better:** Separates CNAs and CWEs into distinct columns.

**Benefits:**
- CNAs on left side, CWEs on right side
- No CNA-to-CNA or CWE-to-CWE connections cluttering view
- Clearer to follow individual associations
- Can sort by connection count

**Implementation:**
- Force-directed but with X-axis constraints
- CNAs locked to x=100, CWEs locked to x=700

## 6. **Clustered Force Graph** (Current + Improvements)
**Why improve current:** Add clustering and better visual encoding.

**Improvements to current visualization:**
- Add community detection (CNAs that share CWEs cluster together)
- Use convex hulls to show clusters
- Add mini-map for navigation
- Filter by CWE category or CNA
- Search functionality
- Time-slider for temporal analysis

## 7. **Sunburst/Radial Partition**
**Why it's interesting:** Shows hierarchical data in a compact circular form.

**Benefits:**
- Multiple levels of hierarchy
- Space-efficient
- Can show CWE categories → specific CWEs → CNAs
- Interactive zooming

## 8. **Network + Timeline (Temporal Analysis)**
**Why it's valuable:** Shows how relationships evolve over time.

**Benefits:**
- See which CWEs are trending
- Track CNA activity over time
- Identify seasonal patterns
- Animation of network growth

**Data needed:**
- Add CVE publication date to parsing
- Create time-sliced graphs
- Show evolution as animation

## 9. **Arc Diagram**
**Why it's cleaner:** Linear layout with arcs showing connections.

**Benefits:**
- Nodes in a line
- Arcs above/below show connections
- Less cluttered than force-directed
- Easy to order by metrics

## 10. **3D Force Graph**
**Why it's cool:** Adds depth for better separation of dense clusters.

**Benefits:**
- Uses Z-axis to reduce overlap
- Interactive rotation
- Can encode additional dimensions (size, color, shape)

**Implementation:**
- Use three.js or force-graph-3d library

---

## Recommendations by Use Case

### For **Presentations/Reports**:
1. ✅ Sankey Diagram (shows flow clearly)
2. ✅ Heatmap (easy to understand)

### For **Interactive Exploration**:
1. ✅ Hierarchical Tree (navigable)
2. ✅ Improved current force graph with filters

### For **Data Analysis**:
1. ✅ Heatmap Matrix (quantitative)
2. ✅ Temporal Network (trends)

### For **Pattern Discovery**:
1. ✅ Clustered Force Graph (community detection)
2. ✅ Chord Diagram (circular relationships)

---

## Quick Implementation - Sankey Diagram

I can create a Sankey diagram version quickly. Would you like me to:

1. Create `web/index-sankey.html` with a Sankey visualization?
2. Replace the current force-directed graph?
3. Add a toggle to switch between visualizations?

Let me know which alternative you'd like to see!

---

## New Graph Types - Generated from Extended CVE Data

### ✅ 1. CWE Co-occurrence Map (CWE ↔ CWE)

**Status:** ✅ Implemented  
**File:** `web/data/cwe_cooccurrence_map.json` (121 KB)  
**Visualization:** `web/index-cwe-cooccurrence.html`

**Stats:** 577 CWEs, 903 co-occurrence edges

Reveals which vulnerabilities commonly appear together in the same CVE (e.g., CWE-20 with CWE-89).

### 2. Product Vulnerability Profile (Product ↔ CWE)

**Status:** Generated but too large (7.9 MB)  
**Stats:** 20,329 products, 577 CWEs, 42,534 edges

Shows vulnerability footprints for specific products. Requires filtering/pagination.

### 3. Vendor Vulnerability Profile (Vendor ↔ CWE)

**Status:** Generated (2.7 MB)  
**Stats:** 9,685 vendors, 577 CWEs, 20,583 edges

Links vendors to their most common CWE classes. Indicates systemic development issues.

### 4. Vulnerability Chaining Map (CVE ↔ CVE)

**Status:** Generated but too large (509 MB!)  
**Stats:** 30,525 CVEs, 3.8M temporal links

Links CVEs affecting the same product within 30 days. Needs database backend.

### 5. Shared Reference Map (CVE ↔ CVE)

**Status:** Generated (2.9 MB)  
**Stats:** 2,677 CVEs, 21,423 links

Connects CVEs citing the same references. Reveals research relationships.

### 6. Product Dependency Map (Product ↔ Product)

**Status:** Generated but too large (51 MB)  
**Stats:** 21,024 products, 344,220 edges

Shows shared vulnerable components. Needs database backend.

### 7. CNA-Vendor Reporting Map (CNA ↔ Vendor)

**Status:** Generated (1.8 MB)  
**Stats:** 350 CNAs, 9,718 vendors, 10,261 edges

Shows which CNAs report on which vendors.

---

## Generation Script

Run: `python3 build_alternative_graphs.py`

This creates 7 JSON files in `web/data/` using the same 365-day filter.

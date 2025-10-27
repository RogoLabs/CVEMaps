#!/usr/bin/env python3
"""
Analytical CVE Visualizations
Builds timeline, trending, and distribution analysis graphs.
"""

import os
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

# Add current directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import Config


def parse_cve_analytical_data(data_dir, days_back=365):
    """
    Parse CVE files for analytical visualizations.
    
    Returns:
        dict with:
        - timeline_data: list of CVEs with CVSS scores and dates
        - cwe_monthly_counts: dict of CWE -> month -> count
        - cwe_cvss_scores: dict of CWE -> list of CVSS scores
    """
    timeline_data = []
    cwe_monthly_counts = defaultdict(lambda: defaultdict(int))
    cwe_cvss_scores = defaultdict(list)
    
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
            if total_files % 10000 == 0:
                print(f"Processed {total_files} files...")
            
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
                        continue
                else:
                    continue
                
                parsed_files += 1
                
                # Extract CNA
                cna = cve_metadata.get("assignerShortName") or cve_metadata.get("assignerOrgId", "Unknown")
                
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
                for adp in adp_containers:
                    problem_types = adp.get("problemTypes", [])
                    for problem_type in problem_types:
                        descriptions = problem_type.get("descriptions", [])
                        for desc in descriptions:
                            if desc.get("type") == "CWE":
                                cwe_value = desc.get("cweId") or desc.get("value")
                                if cwe_value and cwe_value.startswith("CWE-"):
                                    cwes_found.add(cwe_value)
                
                # Extract CVSS scores
                cvss_score = None
                cvss_vector = None
                cvss_severity = None
                
                # Try CNA metrics first
                metrics = cna_container.get("metrics", [])
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        cvss_score = metric["cvssV3_1"].get("baseScore")
                        cvss_vector = metric["cvssV3_1"].get("vectorString")
                        cvss_severity = metric["cvssV3_1"].get("baseSeverity")
                        break
                    elif "cvssV3_0" in metric:
                        cvss_score = metric["cvssV3_0"].get("baseScore")
                        cvss_vector = metric["cvssV3_0"].get("vectorString")
                        cvss_severity = metric["cvssV3_0"].get("baseSeverity")
                        break
                
                # Try ADP metrics if not found
                if cvss_score is None:
                    for adp in adp_containers:
                        metrics = adp.get("metrics", [])
                        for metric in metrics:
                            if "cvssV3_1" in metric:
                                cvss_score = metric["cvssV3_1"].get("baseScore")
                                cvss_vector = metric["cvssV3_1"].get("vectorString")
                                cvss_severity = metric["cvssV3_1"].get("baseSeverity")
                                break
                            elif "cvssV3_0" in metric:
                                cvss_score = metric["cvssV3_0"].get("baseScore")
                                cvss_vector = metric["cvssV3_0"].get("vectorString")
                                cvss_severity = metric["cvssV3_0"].get("baseSeverity")
                                break
                        if cvss_score:
                            break
                
                # Count affected products
                affected_count = 0
                affected_list = cna_container.get("affected", [])
                for affected in affected_list:
                    vendor = affected.get("vendor", "")
                    product = affected.get("product", "")
                    if vendor and product:
                        affected_count += 1
                
                # Add to timeline data if has CVSS score
                if cvss_score is not None and pub_date:
                    timeline_data.append({
                        "cve_id": cve_id,
                        "date": pub_date.strftime("%Y-%m-%d"),
                        "timestamp": pub_date.isoformat(),
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity or "UNKNOWN",
                        "cvss_vector": cvss_vector,
                        "cna": cna,
                        "cwes": list(cwes_found),
                        "affected_count": affected_count
                    })
                
                # Track CWE monthly trends
                if cwes_found:
                    month_key = pub_date.strftime("%Y-%m")
                    for cwe in cwes_found:
                        cwe_monthly_counts[cwe][month_key] += 1
                        
                        # Track CVSS scores by CWE
                        if cvss_score is not None:
                            cwe_cvss_scores[cwe].append(cvss_score)
                
            except Exception as e:
                continue
    
    print(f"\nParsing complete!")
    print(f"Total files: {total_files}")
    print(f"Parsed successfully: {parsed_files}")
    print(f"CVEs with CVSS scores: {len(timeline_data)}")
    print(f"CWEs tracked: {len(cwe_monthly_counts)}")
    
    return {
        "timeline_data": timeline_data,
        "cwe_monthly_counts": dict(cwe_monthly_counts),
        "cwe_cvss_scores": dict(cwe_cvss_scores)
    }


def build_attack_surface_timeline(data, output_file):
    """
    Build attack surface timeline showing CVSS scores over time.
    """
    print("\n[1/3] Building attack surface timeline...")
    
    # Sort by date
    timeline = sorted(data["timeline_data"], key=lambda x: x["timestamp"])
    
    # Calculate daily aggregates
    daily_stats = defaultdict(lambda: {
        "count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "avg_score": 0,
        "max_score": 0,
        "scores": []
    })
    
    for cve in timeline:
        date = cve["date"]
        score = cve["cvss_score"]
        
        daily_stats[date]["count"] += 1
        daily_stats[date]["scores"].append(score)
        daily_stats[date]["max_score"] = max(daily_stats[date]["max_score"], score)
        
        if score >= 9.0:
            daily_stats[date]["critical_count"] += 1
        elif score >= 7.0:
            daily_stats[date]["high_count"] += 1
        elif score >= 4.0:
            daily_stats[date]["medium_count"] += 1
        else:
            daily_stats[date]["low_count"] += 1
    
    # Calculate averages
    for date, stats in daily_stats.items():
        if stats["scores"]:
            stats["avg_score"] = round(sum(stats["scores"]) / len(stats["scores"]), 2)
        del stats["scores"]
    
    output_data = {
        "timeline": timeline,
        "daily_aggregates": [
            {"date": date, **stats}
            for date, stats in sorted(daily_stats.items())
        ],
        "metadata": {
            "total_cves": len(timeline),
            "date_range": {
                "start": timeline[0]["date"] if timeline else None,
                "end": timeline[-1]["date"] if timeline else None
            }
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"✓ Attack surface timeline saved to {output_file}")
    print(f"  {len(timeline)} CVEs with CVSS scores")
    print(f"  Date range: {output_data['metadata']['date_range']['start']} to {output_data['metadata']['date_range']['end']}")


def build_cwe_trending(data, output_file):
    """
    Build CWE trending analysis showing month-over-month changes.
    """
    print("\n[2/3] Building CWE trending analysis...")
    
    cwe_monthly = data["cwe_monthly_counts"]
    
    # Get all months and sort
    all_months = set()
    for cwe, months in cwe_monthly.items():
        all_months.update(months.keys())
    
    sorted_months = sorted(list(all_months))
    
    # Calculate trends for each CWE
    cwe_trends = []
    
    for cwe, months in cwe_monthly.items():
        # Get total count
        total_count = sum(months.values())
        
        # Get monthly values
        monthly_values = [months.get(month, 0) for month in sorted_months]
        
        # Calculate trend (comparing first half vs second half of period)
        if len(monthly_values) >= 2:
            mid_point = len(monthly_values) // 2
            first_half_avg = sum(monthly_values[:mid_point]) / mid_point if mid_point > 0 else 0
            second_half_avg = sum(monthly_values[mid_point:]) / (len(monthly_values) - mid_point)
            
            if first_half_avg > 0:
                trend_percent = ((second_half_avg - first_half_avg) / first_half_avg) * 100
            else:
                trend_percent = 100.0 if second_half_avg > 0 else 0
            
            trend_direction = "up" if trend_percent > 10 else ("down" if trend_percent < -10 else "stable")
        else:
            trend_percent = 0
            trend_direction = "stable"
        
        cwe_trends.append({
            "cwe": cwe,
            "total_count": total_count,
            "monthly_data": [
                {"month": month, "count": months.get(month, 0)}
                for month in sorted_months
            ],
            "trend_percent": round(trend_percent, 1),
            "trend_direction": trend_direction
        })
    
    # Sort by total count
    cwe_trends.sort(key=lambda x: x["total_count"], reverse=True)
    
    output_data = {
        "cwes": cwe_trends[:50],  # Top 50 CWEs
        "months": sorted_months,
        "metadata": {
            "total_cwes": len(cwe_trends),
            "months_analyzed": len(sorted_months)
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"✓ CWE trending saved to {output_file}")
    print(f"  {len(cwe_trends)} CWEs analyzed")
    print(f"  {len(sorted_months)} months of data")
    
    # Show top trending up
    trending_up = sorted([c for c in cwe_trends if c["trend_direction"] == "up"], 
                         key=lambda x: x["trend_percent"], reverse=True)[:5]
    if trending_up:
        print(f"  Top trending up: {', '.join([c['cwe'] for c in trending_up])}")


def build_cwe_cvss_distribution(data, output_file):
    """
    Build CVSS score distribution by CWE type.
    """
    print("\n[3/3] Building CVSS distribution by CWE...")
    
    cwe_scores = data["cwe_cvss_scores"]
    
    distributions = []
    
    for cwe, scores in cwe_scores.items():
        if len(scores) < 5:  # Skip CWEs with too few data points
            continue
        
        # Calculate statistics
        sorted_scores = sorted(scores)
        count = len(scores)
        
        # Severity breakdown
        critical = sum(1 for s in scores if s >= 9.0)
        high = sum(1 for s in scores if 7.0 <= s < 9.0)
        medium = sum(1 for s in scores if 4.0 <= s < 7.0)
        low = sum(1 for s in scores if s < 4.0)
        
        # Statistical measures
        mean_score = sum(scores) / count
        median_score = sorted_scores[count // 2]
        min_score = min(scores)
        max_score = max(scores)
        
        # Quartiles
        q1 = sorted_scores[count // 4]
        q3 = sorted_scores[(3 * count) // 4]
        
        distributions.append({
            "cwe": cwe,
            "count": count,
            "mean": round(mean_score, 2),
            "median": round(median_score, 2),
            "min": round(min_score, 2),
            "max": round(max_score, 2),
            "q1": round(q1, 2),
            "q3": round(q3, 2),
            "severity_breakdown": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "all_scores": scores[:100]  # Sample of scores for box plot
        })
    
    # Sort by count
    distributions.sort(key=lambda x: x["count"], reverse=True)
    
    output_data = {
        "distributions": distributions[:50],  # Top 50 CWEs by count
        "metadata": {
            "total_cwes": len(distributions),
            "total_scores": sum(d["count"] for d in distributions)
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"✓ CVSS distribution saved to {output_file}")
    print(f"  {len(distributions)} CWEs with CVSS data")
    print(f"  {output_data['metadata']['total_scores']} total scores")
    
    # Show highest mean scores
    high_severity = sorted(distributions, key=lambda x: x["mean"], reverse=True)[:5]
    print(f"  Highest mean severity: {', '.join([f'{c['cwe']} ({c['mean']})' for c in high_severity])}")


def main():
    """Main execution."""
    config = Config()
    cve_data_dir = config.CVE_DATA_DIR
    output_dir = config.WEB_DATA_DIR
    days_back = config.DAYS_BACK
    
    if not os.path.exists(cve_data_dir):
        print(f"ERROR: CVE data directory not found: {cve_data_dir}")
        sys.exit(1)
    
    config.ensure_output_dir()
    
    print("=" * 60)
    print("Building Analytical CVE Visualizations")
    print("=" * 60)
    
    # Parse data
    print("\nParsing CVE data...")
    data = parse_cve_analytical_data(cve_data_dir, days_back)
    
    # Build visualizations
    build_attack_surface_timeline(data, f"{output_dir}/attack_surface_timeline.json")
    build_cwe_trending(data, f"{output_dir}/cwe_trending.json")
    build_cwe_cvss_distribution(data, f"{output_dir}/cwe_cvss_distribution.json")
    
    print("\n" + "=" * 60)
    print("✓ All analytical visualizations built successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()

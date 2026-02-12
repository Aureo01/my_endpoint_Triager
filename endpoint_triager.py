#!/usr/bin/env python3
import argparse
import json
import os
import re
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Endpoint triage engine powered by weighted risk heuristics---*
CATEGORIES = {
    "auth": {
        "keywords": ["login", "auth", "token", "oauth", "sso", "signin", "signout", "register", "password", "reset", "forgot"],
        "weight": 10,
        "display": "Authentication"
    },
    "admin": {
        "keywords": ["admin", "panel", "dashboard", "manage", "control", "console", "internal", "cpanel", "wp-admin", "superuser", "root"],
        "weight": 12,
        "display": "Admin / Internal"
    },
    "debug": {
        "keywords": ["debug", "test", "staging", "dev", "beta", "qa", "status", "health", "metrics", "info", "actuator"],
        "weight": 6,
        "display": "Debug / Dev"
    },
    "api": {
        "keywords": ["api", "v1", "v2", "v3", "graphql", "data", "rest", "rpc", "swagger", "openapi", "redoc", "docs"],
        "weight": 8,
        "display": "Data / APIs"
    },
    "files": {
        "keywords": [".zip", ".sql", ".env", ".bak", ".backup", ".git", "backup", "dump", "export", "download", "upload", "config", ".yml", ".yaml"],
        "weight": 9,
        "display": "Files / Backups"
    },
    "high_risk": {
        "keywords": ["upload", "import", "export", "exec", "cmd", "execute", "shell", "run", "command", "eval", "compile"],
        "weight": 15,
        "display": "High Risk Operations"
    }
}

# Parameter threat modeling with severity weighting
DANGEROUS_PARAMS = {
    "critical": ["cmd", "exec", "command", "script", "load", "eval", "compile"],
    "high": ["file", "path", "url", "redirect", "callback", "include", "require"],
    "medium": ["id", "user", "profile", "account", "role", "admin"]
}

def classify_url(url, aggressive=False):
    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()
    query_params = parse_qs(parsed.query)

    categories = []
    total_score = 0
    dangerous_params = {"critical": [], "high": [], "medium": []}
    vulnerability_hints = []

    # Path-based classificationn
    for cat_key, cat_config in CATEGORIES.items():
        for keyword in cat_config["keywords"]:
            if keyword in path:
                categories.append(cat_config["display"])
                total_score += cat_config["weight"]
                break  # Avoid double-counting same category

    #Query string threat analysis--*
    for param in query_params:
        param_lower = param.lower()
        if param_lower in DANGEROUS_PARAMS["critical"]:
            dangerous_params["critical"].append(param)
            total_score += 15
        elif param_lower in DANGEROUS_PARAMS["high"]:
            dangerous_params["high"].append(param)
            total_score += 10
        elif param_lower in DANGEROUS_PARAMS["medium"]:
            dangerous_params["medium"].append(param)
            total_score += 5

    #Aggressive heuristic engine for high-impact exploit indicators
    if aggressive:
        # IDOR patterns
        idor_patterns = ["id=", "user=", "profile=", "account=", "uid=", "userid="]
        if any(pattern in query for pattern in idor_patterns):
            vulnerability_hints.append("Potential IDOR")
            total_score += 8

        # SSRF patterns
        ssrf_patterns = ["url=", "redirect=", "file=", "path=", "callback=", "next=", "return="]
        if any(pattern in query for pattern in ssrf_patterns):
            vulnerability_hints.append("Potential SSRF")
            total_score += 12

        # RCE patterns
        rce_patterns = ["cmd=", "exec=", "command=", "script=", "eval="]
        if any(pattern in query for pattern in rce_patterns):
            vulnerability_hints.append("Potential RCE")
            total_score += 20

    # Determine severity based on score
    if total_score >= 25:
        severity = "CRITICAL"
    elif total_score >= 15:
        severity = "HIGH"
    elif total_score >= 8:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "url": url,
        "categories": list(set(categories)),
        "score": total_score,
        "severity": severity,
        "dangerous_params": dangerous_params,
        "vulnerability_hints": vulnerability_hints
    }

def load_urls(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip().startswith(("http://", "https://"))]

def print_results_table(results):
    table = Table(title="Endpoint Classification Results", show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Score", style="green")
    table.add_column("Categories", style="yellow")
    table.add_column("Vuln Hints", style="red")
    table.add_column("URL", style="blue", overflow="fold")

    for r in sorted(results, key=lambda x: (-x["score"], x["url"])):
        if r["categories"]:
            categories_str = ", ".join(r["categories"])
            vuln_hints_str = ", ".join(r["vulnerability_hints"]) if r["vulnerability_hints"] else "-"
            
            # Color-coded severity
            severity_color = "red" if r["severity"] == "CRITICAL" else "orange" if r["severity"] == "HIGH" else "yellow" if r["severity"] == "MEDIUM" else "green"
            
            table.add_row(
                f"[{severity_color}]{r['severity']}[/{severity_color}]",
                str(r["score"]),
                categories_str,
                vuln_hints_str,
                r["url"]
            )

    console.print(table)

def save_by_severity(results, output_dir="triage_results"):
    os.makedirs(output_dir, exist_ok=True)
    
    # Group by severity
    severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    category_groups = {}
    
    for r in results:
        if r["categories"]:  # Only save classified endpoints
            severity_groups[r["severity"]].append(r)
            
            # Group by categories
            for cat in r["categories"]:
                if cat not in category_groups:
                    category_groups[cat] = []
                category_groups[cat].append(r)

    # Write results segmented by severity
    for severity, items in severity_groups.items():
        if items:
            path = os.path.join(output_dir, f"{severity.lower()}_endpoints.txt")
            with open(path, "w") as f:
                for item in sorted(items, key=lambda x: -x["score"]):
                    f.write(f"{item['url']}\n")
            console.print(f"{len(items)} endpoints saved to: {path}")

    # Save by category
    for category, items in category_groups.items():
        filename = category.replace(" ", "_").replace("/", "_") + ".txt"
        path = os.path.join(output_dir, filename)
        with open(path, "w") as f:
            for item in sorted(items, key=lambda x: -x["score"]):
                f.write(f"{item['url']}\n")

    #full JSON report
    with open(os.path.join(output_dir, "full_report.json"), "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"Full report: {output_dir}/full_report.json")

def print_summary(results):
    total = len(results)
    classified = len([r for r in results if r["categories"]])
    critical = len([r for r in results if r["severity"] == "CRITICAL"])
    high = len([r for r in results if r["severity"] == "HIGH"])
    medium = len([r for r in results if r["severity"] == "MEDIUM"])
    low = len([r for r in results if r["severity"] == "LOW"])

    panel = Panel(
        f"""
Summary:
  - Total URLs: {total}
  - Classified endpoints: {classified}
  - CRITICAL: {critical}
  - HIGH: {high}
  - MEDIUM: {medium}
  - LOW: {low}
        """,
        title="Endpoint Triager - Analysis Summary",
        expand=False
    )
    console.print(panel)

def main():
    parser = argparse.ArgumentParser(description="Advanced endpoint triage and risk classification")
    parser.add_argument("-w", "--wordlist", required=True, help="File containing URLs (one per line)")
    parser.add_argument("--output-dir", default="triage_results", help="Output directory for results")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive vulnerability pattern detection")
    parser.add_argument("--min-score", type=int, default=0, help="Minimum score threshold to include in results")
    args = parser.parse_args()

    urls = load_urls(args.wordlist)
    if not urls:
        console.print("[red]No valid URLs found (must start with http:// or https://)[/red]")
        return

    console.print(f"[blue]Analyzing {len(urls)} URLs...[/blue]")

    results = [classify_url(url, aggressive=args.aggressive) for url in urls]
    
    # Gate results by minimum risk score
    if args.min_score > 0:
        results = [r for r in results if r["score"] >= args.min_score]

    if not any(r["categories"] for r in results):
        console.print("[yellow]No endpoints matched classification criteria.[/yellow]")
        return

    print_results_table(results)
    print_summary(results)
    save_by_severity(results, output_dir=args.output_dir)

if __name__ == "__main__":
    main()

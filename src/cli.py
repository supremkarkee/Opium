from __future__ import annotations

import argparse
import csv
from pathlib import Path

from tabulate import tabulate

from src.loaders import (
    get_cve_records,
    load_asset_list,
    load_epss_scores,
    load_json,
    load_kev_ids,
)
from src.matcher import match_cves_for_assets
from src.normaliser import normalise_asset_name
from src.ranker import rank_matches


def write_csv(rows: list[dict], out_path: str | Path) -> None:
    """Save ranked vulnerabilities into a CSV file."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        out_path.write_text("No matching CVEs found.\n", encoding="utf-8")
        return

    fieldnames = [
        "urgency",
        "priority_score",
        "asset",
        "cve_id",
        "cvss",
        "epss",
        "epss_percentile",
        "kev",
        "match_confidence",
        "vendor",
        "product",
        "matched_cpe",
        "summary",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="CVE-to-My-Stack Translator CLI Tool")
    parser.add_argument("--assets", required=True, help="Path to asset list text file (e.g. data/sample_asset_list.txt)")
    parser.add_argument("--cve", required=True, help="Path to local CVE JSON file (e.g. data/sample_cve_data.json)")
    parser.add_argument("--kev", required=False, help="Path to local CISA KEV JSON file (e.g. data/sample_kev_data.json)")
    parser.add_argument("--epss", required=False, help="Path to local EPSS CSV file (e.g. data/sample_epss_data.csv)")
    parser.add_argument("--out", default="output/priority_results.csv", help="Output CSV path")
    parser.add_argument("--limit", type=int, default=20, help="Number of rows to print in console preview")
    args = parser.parse_args()

    print("[1/6] Loading assets...")
    assets = load_asset_list(args.assets)

    print("[2/6] Normalising asset names...")
    normalised_assets = [normalise_asset_name(asset["name"]) for asset in assets]

    print("\nNormalisation results:")
    print(tabulate(
        [
            [
                a["original"],
                "Yes" if a["matched"] else "No",
                a["matched_alias"],
                a["vendor"],
                a["product"],
                a["confidence"],
            ]
            for a in normalised_assets
        ],
        headers=["Original", "Matched", "Alias", "Vendor", "Product", "Confidence"],
        tablefmt="github",
    ))

    print("\n[3/6] Loading CVE data...")
    raw_cve = load_json(args.cve)
    cve_records = get_cve_records(raw_cve)
    print(f"Loaded {len(cve_records):,} CVE records.")

    print("[4/6] Loading KEV and EPSS...")
    kev_ids = load_kev_ids(args.kev)
    epss_scores = load_epss_scores(args.epss)
    print(f"Loaded {len(kev_ids):,} KEV IDs.")
    print(f"Loaded {len(epss_scores):,} EPSS scores.")

    print("[5/6] Matching CVEs to assets...")
    matches = match_cves_for_assets(cve_records, normalised_assets)
    print(f"Found {len(matches):,} raw CVE/asset matches.")

    print("[6/6] Ranking and writing output...")
    ranked = rank_matches(matches, kev_ids, epss_scores)
    write_csv(ranked, args.out)

    print(f"\nSaved output to: {args.out}")

    if ranked:
        preview = ranked[: args.limit]
        print("\nTop priority results:")
        print(tabulate(
            [
                [
                    row["urgency"],
                    row["asset"],
                    row["cve_id"],
                    row["cvss"],
                    row["epss"],
                    row["kev"],
                    row["summary"][:90] + ("..." if len(row["summary"]) > 90 else ""),
                ]
                for row in preview
            ],
            headers=["Urgency", "Asset", "CVE", "CVSS", "EPSS", "KEV", "Summary"],
            tablefmt="github",
        ))
    else:
        print("\nNo matching CVEs found. Check normalisation vendor/product values against the CPE dictionary.")


if __name__ == "__main__":
    main()

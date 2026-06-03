from pathlib import Path
import json
import pandas as pd
from loaders import load_json, get_cve_records, load_kev_ids, load_asset_list
from matcher import collect_cpes, get_cve_id, get_description, get_cvss_score

def check_epss(path):
    print("\n[1] EPSS CSV CHECK")
    if not Path(path).exists():
        print(f"Missing EPSS file: {path}")
        return

    df = pd.read_csv(path, comment="#")
    print("Columns:", list(df.columns))
    print("Rows:", len(df))

    if "epss" in df.columns:
        df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
        print("EPSS min:", df["epss"].min())
        print("EPSS max:", df["epss"].max())
    else:
        print("ERROR: epss column not found")

def check_kev(path):
    print("\n[2] KEV JSON CHECK")
    if not Path(path).exists():
        print(f"Missing KEV file: {path}")
        return

    kev_ids = load_kev_ids(path)
    print("KEV type:", type(kev_ids))
    print("KEV CVE count:", len(kev_ids))
    print("First 5 KEV IDs:", list(kev_ids)[:5])

def check_cve(path):
    print("\n[3] CVE JSON CHECK")
    if not Path(path).exists():
        print(f"Missing CVE file: {path}")
        return

    raw = load_json(path)
    print("Top-level type:", type(raw))

    if isinstance(raw, dict):
        print("Top-level keys:", list(raw.keys()))

    records = get_cve_records(raw)
    print("CVE record count:", len(records))

    if records:
        first = records[0]
        print("First CVE ID:", get_cve_id(first))
        print("First CVSS:", get_cvss_score(first))
        print("First description:", get_description(first)[:150])

        cpes = collect_cpes(first)
        print("CPE count in first CVE:", len(cpes))
        print("First 3 CPEs:", cpes[:3])

def check_assets(path):
    print("\n[4] ASSET LIST CHECK")
    if not Path(path).exists():
        print(f"Missing asset file: {path}")
        return

    assets = load_asset_list(path)
    print("Asset count:", len(assets))
    print("Assets:")
    for asset in assets:
        print("-", asset)

if __name__ == "__main__":
    check_epss("tests/fixtures/epss_scores.csv")
    check_kev("tests/fixtures/known_exploited_vulnerabilities.json")
    check_cve("tests/fixtures/CVE-test.json")
    check_assets("data/sample_asset_list.txt")

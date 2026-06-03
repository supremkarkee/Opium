from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    """Load a JSON file from disk."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_cve_records(raw_json: Any) -> list[dict]:
    """
    Return a list of CVE records from different possible NVD/FKIE JSON formats.
    Supports:
    - {"vulnerabilities": [...]}
    - {"CVE_Items": [...]}
    - [ ... ]
    """
    if isinstance(raw_json, list):
        return raw_json

    if isinstance(raw_json, dict):
        if isinstance(raw_json.get("vulnerabilities"), list):
            return raw_json["vulnerabilities"]
        if isinstance(raw_json.get("CVE_Items"), list):
            return raw_json["CVE_Items"]
        if isinstance(raw_json.get("cves"), list):
            return raw_json["cves"]

    raise ValueError("Unsupported CVE JSON structure. Open the JSON and check the top-level keys.")


def load_kev_ids(path: str | Path | None) -> set[str]:
    """Load CISA KEV CVE IDs into a set for fast lookup."""
    if not path:
        return set()

    raw = load_json(path)
    vulnerabilities = raw.get("vulnerabilities", []) if isinstance(raw, dict) else []

    kev_ids: set[str] = set()
    for item in vulnerabilities:
        cve_id = item.get("cveID") or item.get("cveId") or item.get("cve")
        if cve_id:
            kev_ids.add(cve_id.strip().upper())

    return kev_ids


def load_epss_scores(path: str | Path | None) -> dict[str, dict[str, float]]:
    """
    Load EPSS CSV into a dictionary:
    {
      "CVE-2025-1234": {"epss": 0.123, "percentile": 0.95}
    }
    """
    if not path:
        return {}

    path = Path(path)
    if not path.exists():
        return {}

    scores: dict[str, dict[str, float]] = {}

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(row for row in f if not row.startswith("#"))
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue

            try:
                epss = float(row.get("epss") or 0)
            except ValueError:
                epss = 0.0

            try:
                percentile = float(row.get("percentile") or 0)
            except ValueError:
                percentile = 0.0

            scores[cve] = {"epss": epss, "percentile": percentile}

    return scores


def load_asset_list(path: str | Path) -> list[dict[str, str]]:
    """
    Load a simple asset list.

    Supported line formats:
    - Google Chrome, Latest
    - OpenSSL, 3.0.7
    - Moodle
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Asset list not found: {path}")

    assets: list[dict[str, str]] = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if not clean or clean.lower().startswith("product"):
                continue

            if "," in clean:
                name, version = [part.strip() for part in clean.split(",", 1)]
            else:
                name, version = clean, ""

            assets.append({"name": name, "version": version})

    return assets

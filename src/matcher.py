from __future__ import annotations

from typing import Any


def get_cve_id(record: dict) -> str:
    cve = record.get("cve", {})

    if isinstance(cve, dict):
        if cve.get("id"):
            return str(cve["id"]).upper()
        meta = cve.get("CVE_data_meta", {})
        if isinstance(meta, dict) and meta.get("ID"):
            return str(meta["ID"]).upper()

    if record.get("id"):
        return str(record["id"]).upper()

    return ""


def get_description(record: dict) -> str:
    cve = record.get("cve", {})

    # NVD 2.0 style
    descriptions = cve.get("descriptions", []) if isinstance(cve, dict) else []
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")

    # Legacy style
    legacy_data = cve.get("description", {}).get("description_data", []) if isinstance(cve, dict) else []
    for item in legacy_data:
        if item.get("lang") == "en":
            return item.get("value", "")

    return ""


def get_cvss_score(record: dict) -> float:
    cve = record.get("cve", {})
    metrics = {}

    if isinstance(cve, dict):
        metrics = cve.get("metrics", {}) or {}

    if not metrics:
        metrics = record.get("metrics", {}) or {}

    metric_keys = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV3",
        "cvssMetricV2",
    ]

    for key in metric_keys:
        values = metrics.get(key)
        if isinstance(values, list) and values:
            cvss_data = values[0].get("cvssData", {})
            try:
                return float(cvss_data.get("baseScore", 0))
            except (TypeError, ValueError):
                return 0.0

    # Legacy NVD style
    impact = record.get("impact", {})
    for legacy_key in ["baseMetricV3", "baseMetricV2"]:
        base = impact.get(legacy_key, {})
        cvss_data = base.get("cvssV3") or base.get("cvssV2") or {}
        if "baseScore" in cvss_data:
            try:
                return float(cvss_data["baseScore"])
            except (TypeError, ValueError):
                return 0.0

    return 0.0


def collect_cpes(obj: Any) -> list[str]:
    """Recursively collect CPE strings from a CVE record."""
    found: list[str] = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in {"criteria", "cpe23Uri", "cpeName"} and isinstance(value, str):
                if value.startswith("cpe:"):
                    found.append(value)
            else:
                found.extend(collect_cpes(value))

    elif isinstance(obj, list):
        for item in obj:
            found.extend(collect_cpes(item))

    return found


def cpe_matches_asset(cpe: str, vendor: str, product: str) -> bool:
    """
    Match by CPE vendor/product.

    Example CPE:
    cpe:2.3:a:google:chrome:...
    """
    needle = f":{vendor}:{product}:".lower()
    return needle in cpe.lower()


def match_cves_for_assets(cve_records: list[dict], normalised_assets: list[dict]) -> list[dict]:
    """Return all CVEs that match at least one normalised asset."""
    matches: list[dict] = []

    usable_assets = [a for a in normalised_assets if a.get("matched")]

    for record in cve_records:
        cve_id = get_cve_id(record)
        if not cve_id:
            continue

        cpes = collect_cpes(record)

        if not cpes:
            continue

        for asset in usable_assets:
            vendor = str(asset.get("vendor", ""))
            product = str(asset.get("product", ""))

            matched_cpe = next((cpe for cpe in cpes if cpe_matches_asset(cpe, vendor, product)), None)

            if matched_cpe:
                matches.append({
                    "cve_id": cve_id,
                    "asset_name": asset["original"],
                    "vendor": vendor,
                    "product": product,
                    "match_confidence": asset["confidence"],
                    "matched_cpe": matched_cpe,
                    "cvss": get_cvss_score(record),
                    "description": get_description(record),
                })

    return matches

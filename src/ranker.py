from __future__ import annotations


def epss_label(epss: float) -> str:
    if epss >= 0.70:
        return "high"
    if epss >= 0.30:
        return "moderate"
    return "low"


def urgency_bucket(is_kev: bool, epss: float, cvss: float) -> str:
    if is_kev:
        return "Fix today"
    if epss >= 0.70 or cvss >= 9.0:
        return "Fix this week"
    if epss >= 0.30 or cvss >= 7.0:
        return "Review soon"
    return "Monitor"


def plain_english_summary(cve_id: str, asset: str, is_kev: bool, epss: float, cvss: float) -> str:
    kev_text = "It is in the KEV catalogue, meaning it has confirmed real-world exploitation." if is_kev else "It is not currently flagged in KEV."
    return (
        f"{cve_id} affects {asset}. CVSS is {cvss:.1f} and EPSS indicates {epss_label(epss)} "
        f"exploitation probability. {kev_text}"
    )


def rank_matches(matches: list[dict], kev_ids: set[str], epss_scores: dict[str, dict[str, float]]) -> list[dict]:
    ranked: list[dict] = []

    seen = set()

    for item in matches:
        cve_id = item["cve_id"].upper()
        key = (cve_id, item["asset_name"])

        if key in seen:
            continue

        seen.add(key)

        is_kev = cve_id in kev_ids
        epss = float(epss_scores.get(cve_id, {}).get("epss", 0))
        percentile = float(epss_scores.get(cve_id, {}).get("percentile", 0))
        cvss = float(item.get("cvss", 0))

        # KEV first, then EPSS, then CVSS.
        priority_score = (1000 if is_kev else 0) + (epss * 100) + cvss

        result = {
            "urgency": urgency_bucket(is_kev, epss, cvss),
            "priority_score": round(priority_score, 2),
            "asset": item["asset_name"],
            "cve_id": cve_id,
            "cvss": cvss,
            "epss": epss,
            "epss_percentile": percentile,
            "kev": "Yes" if is_kev else "No",
            "match_confidence": item["match_confidence"],
            "vendor": item["vendor"],
            "product": item["product"],
            "matched_cpe": item["matched_cpe"],
            "summary": plain_english_summary(cve_id, item["asset_name"], is_kev, epss, cvss),
        }

        ranked.append(result)

    ranked.sort(key=lambda row: row["priority_score"], reverse=True)
    return ranked

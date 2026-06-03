from __future__ import annotations

from rapidfuzz import process, fuzz


# MVP dictionary. Verify and adjust vendor/product values using the CPE dictionary on the day.
NORMALISATION_MAP: dict[str, dict[str, str]] = {
    "microsoft 365 apps for business": {"vendor": "microsoft", "product": "365_apps"},
    "office 365": {"vendor": "microsoft", "product": "365_apps"},
    "ms 365": {"vendor": "microsoft", "product": "365_apps"},

    "windows server 2022": {"vendor": "microsoft", "product": "windows_server_2022"},
    "windows server": {"vendor": "microsoft", "product": "windows_server_2022"},
    "windows 10 pro": {"vendor": "microsoft", "product": "windows_10"},
    "windows 10": {"vendor": "microsoft", "product": "windows_10"},

    "adobe acrobat reader dc": {"vendor": "adobe", "product": "acrobat_reader_dc"},
    "acrobat reader": {"vendor": "adobe", "product": "acrobat_reader_dc"},

    "cisco ios xe": {"vendor": "cisco", "product": "ios_xe"},
    "vmware vsphere": {"vendor": "vmware", "product": "vsphere"},
    "vsphere": {"vendor": "vmware", "product": "vsphere"},

    "google chrome": {"vendor": "google", "product": "chrome"},
    "chrome": {"vendor": "google", "product": "chrome"},

    "openssl": {"vendor": "openssl", "product": "openssl"},
    "apache http server": {"vendor": "apache", "product": "http_server"},
    "apache web server": {"vendor": "apache", "product": "http_server"},

    "zoom": {"vendor": "zoom", "product": "zoom"},
    "wordpress": {"vendor": "wordpress", "product": "wordpress"},
    "moodle": {"vendor": "moodle", "product": "moodle"},
}


def normalise_asset_name(asset_name: str, threshold: int = 75) -> dict[str, object]:
    """
    Convert informal user software names into a vendor/product pair.

    Returns:
    {
      "original": "Google Chrome",
      "matched_alias": "google chrome",
      "vendor": "google",
      "product": "chrome",
      "confidence": 100,
      "matched": True
    }
    """
    cleaned = asset_name.strip().lower()

    best = process.extractOne(
        cleaned,
        NORMALISATION_MAP.keys(),
        scorer=fuzz.WRatio,
    )

    if not best:
        return {
            "original": asset_name,
            "matched_alias": "",
            "vendor": "",
            "product": "",
            "confidence": 0,
            "matched": False,
        }

    alias, score, _ = best

    if score < threshold:
        return {
            "original": asset_name,
            "matched_alias": alias,
            "vendor": "",
            "product": "",
            "confidence": round(score, 2),
            "matched": False,
        }

    mapped = NORMALISATION_MAP[alias]
    return {
        "original": asset_name,
        "matched_alias": alias,
        "vendor": mapped["vendor"],
        "product": mapped["product"],
        "confidence": round(score, 2),
        "matched": True,
    }

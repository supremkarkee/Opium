# 5-minute demo script

## 1. Problem, 45 seconds

Small IT teams receive too many CVEs. A solo sysadmin does not have time to read every vulnerability notice and manually check whether it affects their company.

## 2. Scenario, 45 seconds

We chose Scenario 1: Alex, a solo SMB system administrator at a 40-person accountancy firm. He runs Microsoft 365, Windows Server, Chrome, OpenSSL, Apache, and other common software.

## 3. Tool flow, 1 minute

Our tool:
1. Loads the asset list.
2. Normalises informal software names.
3. Searches the local CVE JSON file for matching CPE entries.
4. Adds KEV and EPSS risk signals.
5. Produces a short, ranked patch-priority list.

## 4. Live demo, 1.5 minutes

Run:

```bash
python src/app.py --assets data/sample_asset_list.txt --cve data/CVE-2025.json --kev data/known_exploited_vulnerabilities.json --epss data/epss_scores.csv --out output/priority_results.csv
```

Show:
- matched assets
- KEV yes/no
- CVSS
- EPSS
- plain-English action

## 5. Limitations, 45 seconds

The hardest part is normalisation. If a product name is mapped to the wrong vendor/product string, a real CVE could be missed silently. We reduce this risk by using a controlled dictionary and match confidence scores.

## 6. Future improvement, 30 seconds

Add version-range matching, browser dashboard, and asset criticality such as "internet-facing" or "business critical".

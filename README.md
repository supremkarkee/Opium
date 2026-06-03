# CVE-to-My-Stack Translator

A 2-hour MVP for the CyberHack "CVE-to-My-Stack Translator" project.

## What it does

This Python CLI tool takes a small asset list, maps informal software names to vendor/product identifiers, searches a local CVE JSON file for matching CPE entries, adds KEV and EPSS information, and produces a prioritised CSV/table for a small IT administrator.

## MVP scope

- Scenario: Solo SMB System Administrator
- Approach: Python CLI data pipeline
- No Docker
- No database
- Local files only

## Project structure

```text
cve-to-my-stack-translator/
├── data/
│   ├── CVE-2025.json
│   ├── known_exploited_vulnerabilities.json
│   ├── epss_scores.csv
│   └── sample_asset_list.txt
├── docs/
│   └── demo_script.md
├── output/
│   └── priority_results.csv
├── src/
│   ├── app.py
│   ├── loaders.py
│   ├── normalisation.py
│   ├── matcher.py
│   └── ranker.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```bash
.\.venv\Scripts\Activate.ps1
```

Install packages:

```bash
pip install -r requirements.txt
```

## Run

Put the real hackathon data files into the `data/` folder, then run:

```bash
python src/app.py --assets data/sample_asset_list.txt --cve data/CVE-2025.json --kev data/known_exploited_vulnerabilities.json --epss data/epss_scores.csv --out output/priority_results.csv
```

If EPSS is not ready yet, run without it:

```bash
python src/app.py --assets data/sample_asset_list.txt --cve data/CVE-2025.json --kev data/known_exploited_vulnerabilities.json --out output/priority_results.csv
```

## Team roles

| Role | Person | Main files |
|---|---|---|
| Data loader | Teammate 1 | `loaders.py`, CVE/KEV/EPSS loading |
| Normalisation | Teammate 2 | `normalisation.py`, product mapping |
| Output/demo | Teammate 3 | `ranker.py`, `app.py`, README/demo script |

## Demo line

"Alex is the only IT admin for a 40-person accountancy firm. Instead of reading every new CVE, he uploads his asset list. Our tool filters only the CVEs that affect his software and ranks them using KEV, EPSS, and CVSS."

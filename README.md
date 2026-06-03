# 🛡️ CVE-to-My-Stack Translator

A premium, lightweight Python CLI tool designed for solo IT administrators and small teams to translate informal asset names into standardized vendor/product CPE keys, map them against CVE entries, and prioritize vulnerability patching using real-world risk signals (CISA KEV and EPSS).

---

## ✨ Key Features

- **⚡ Fast-Forward Prioritization**: Instead of parsing thousands of vulnerabilities manually, map and prioritize fixes tailored specifically to your software stack.
- **🔍 Intelligent Software Normalisation**: Leverages fuzzy matching (`rapidfuzz`) to align informal asset names (e.g. `"ms 365"`, `"chrome"`) with official CPE dictionary vendor and product identifiers.
- **🎯 CPE-Based CVE Matching**: Automatically searches raw NVD 1.1 or 2.0 style CVE JSON datasets, extracting relevant vulnerabilities using CPE tree metrics.
- **🚦 Composite Risk Ranking**: Computes an action-oriented composite priority score using:
  - **CISA KEV (Known Exploited Vulnerabilities)** (Highest urgency/confirmed exploitation)
  - **EPSS (Exploit Prediction Scoring System)** (Likelihood of active exploitation)
  - **CVSS Score** (Vulnerability severity)
- **📋 Urgency Categorization**: Classifies results into immediate action buckets: *Fix today*, *Fix this week*, *Review soon*, or *Monitor*.

---

## 📁 Clean Project Structure

The project has been streamlined for maximum readability and ease of execution:

```text
Opium/
├── data/
│   ├── sample_asset_list.txt             # Your stack list (informal names, versions)
│   ├── sample_cve_data.json              # Mock CVE dataset for testing
│   ├── sample_epss_data.csv              # Mock EPSS scoring data
│   └── sample_kev_data.json              # Mock CISA KEV listing
├── src/                                  # Modular logic components
│   ├── __init__.py
│   ├── cli.py                            # CLI orchestration and console outputs
│   ├── loaders.py                        # Data ingestion for JSON, CSV, and asset files
│   ├── matcher.py                        # CPE scanning and CVE matching
│   ├── normaliser.py                     # Asset name fuzzy matching dictionary
│   └── ranker.py                         # Prioritisation ranking and scoring engine
├── .gitignore                            # Local git configuration
├── app.py                                # Minimal CLI entrypoint
├── README.md                             # This documentation
└── requirements.txt                      # Project package requirements (excluding unused packages)
```

---

## 🚀 Getting Started

### 1. Setup Virtual Environment

Create a clean virtual environment and install the required dependencies:

```bash
# Create virtual environment
python -m venv .venv

# Activate it (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate it (Bash/Mac/Linux)
source .venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

### 2. Run the CLI Tool

Run the tool out-of-the-box using the provided sample datasets in `data/`:

```bash
python app.py --assets data/sample_asset_list.txt --cve data/sample_cve_data.json --kev data/sample_kev_data.json --epss data/sample_epss_data.csv --out output/priority_results.csv
```

#### Run with only CVE data (no optional inputs):

```bash
python app.py --assets data/sample_asset_list.txt --cve data/sample_cve_data.json --out output/priority_results.csv
```

---

## 🛠️ Prioritization Logic

Vulnerabilities are ranked using a composite priority score computed as follows:

$$\text{Priority Score} = (\text{is\_KEV} \times 1000) + (\text{EPSS} \times 100) + \text{CVSS}$$

This ensures that:
1. **Fix Today**: Any vulnerability actively exploited in the wild (CISA KEV) is bumped to the top of the list immediately.
2. **Fix This Week**: Non-KEV vulnerabilities with very high probability of exploit (EPSS $\ge$ 70%) or critical severity (CVSS $\ge$ 9.0) are addressed next.
3. **Review Soon / Monitor**: Medium-to-low impact issues are scheduled for standard patch cycles.

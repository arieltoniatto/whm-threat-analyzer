# Email Threat Analysis Project (WHM CTI)

This project is a suite of Python scripts, orchestrated by a main pipeline (`main.py`), developed to automate the analysis of WHM email delivery logs. The goal is to identify potentially compromised accounts and perform a reputation analysis (Threat Intelligence) on the source IP addresses.

The workflow is fully automated: it transforms raw data from a single HTML file into a final CSV report with a risk analysis.

## Workflow Overview

The complete process is initiated by `main.py` and follows this data analysis chain:

```
0. main.py (Orchestrator)
   ↓
 HTML (Raw WHM Log) (in data/00_raw/whm_logs/)
   ↓
1. src/1_collect_whm_data.py
   ↓
 JSON (WHM Analysis) (in data/01_processed/whm_extracted/)
   ↓
2. src/2_process_ips.py
   ↓
 JSON (New IPs) (in data/02_intermediate/ip_lists/)
   ↓
3. src/3_enrich_ips.py
   ↓
 JSON (CTI Report) (in data/03_enriched/ip_reputation/)
   ↓
4. src/4_generate_reports.py
   ↓
 CSV (Final Report) (in reports/)
```

## Script Descriptions

The pipeline is controlled by `main.py`, which executes the following scripts in sequence:

**`main.py` (Orchestrator)**

  * **Role**: This is the project's entry point. It manages the execution of the four scripts from the `src/` folder, passing the output file from one step as the input for the next.
  * **Process**: It validates the existence and format of files at each step and logs the entire process to `pipeline.log`.
  * **Usage**: `python main.py <path/to/html_file.html>`

-----

1.  **`src/1_collect_whm_data.py` (Data Collection)**

      * **Input**: A raw HTML file saved from the WHM "Email Delivery Reports" screen (e.g., `data/00_raw/whm_logs/YY-MM-DD_domain-account.html`).
      * **Process**: Parses the HTML to extract critical data: event, sender, recipient, source IP, date/time, and result message. Applies spam detection logic.
      * **Output**: A JSON file (e.g., `data/01_processed/whm_extracted/YY-MM-DD_whm_domain-account.json`).

2.  **`src/2_process_ips.py` (IP Processing)**

      * **Input**: The JSON file generated in Step 1.
      * **Process**: Extracts the IPs, compares them with a "Master List" (`data/04_persistent/ip_lists/all_ips_master_list.json`), separates "new" from "repeated" IPs, and updates the master list.
      * **Output**: A JSON file (e.g., `data/02_intermediate/ip_lists/YY-MM-DD_new-ips_domain-account.json`) containing only the IPs that need analysis.

3.  **`src/3_enrich_ips.py` (Enrichment/CTI)**

      * **Input**: The JSON file with new IPs from Step 2.
      * **Process**: Queries Threat Intelligence services (ip-api.com, AbuseIPDB, VirusTotal) for each IP. Calculates a "Risk Level" (CRITICAL, HIGH, MEDIUM, LOW, CLEAN).
      * **Output**: A detailed JSON report (e.g., `data/03_enriched/ip_reputation/YY-MM-DD_ip-reputation_domain-account.json`) with the API data and the calculated risk level.

4.  **`src/4_generate_reports.py` (Report Generation)**

      * **Input**: The detailed JSON report from Step 3.
      * **Process**: Uses pandas to flatten the complex JSON structure into a simple tabular format.
      * **Output**: The final report in `.csv` format (e.g., `reports/YY-MM-DD_report_domain-account.csv`), ready for analysis.

-----

## Installation and Dependencies

To run this project, you will need Python 3 and the following libraries. You can install them using pip:

```bash
pip install -r requirements.txt
```

-----

## Folder Structure

The pipeline expects and creates the following folder structure:

```
/
├── main.py                 # Pipeline orchestrator
├── pipeline.log            # Execution log
├── src/                    # Folder with processing scripts
│   ├── 1_collect_whm_data.py
│   ├── 2_process_ips.py
│   ├── 3_enrich_ips.py
│   └── 4_generate_reports.py
├── data/
│   ├── 00_raw/             # Raw input files
│   │   └── whm_logs/
│   │       └── (Place your .html files here)
│   ├── 01_processed/       # Outputs from Step 1
│   │   └── whm_extracted/
│   ├── 02_intermediate/    # Outputs from Step 2 and IP base
│   │   └── ip_lists/
│   │       └── base_ips.json
│   └── 03_enriched/        # Outputs from Step 3
│   │   └── ip_reputation/
│   └── 04_persistent       # ips master list and known ips
└── reports/                # Final reports (Output from Step 4)
```

-----

## Configuration

Before running, some configuration is required in the scripts inside the `src/` folder:

### 1\. API Keys (Required)

The `src/3_enrich_ips.py` script requires API keys for AbuseIPDB and VirusTotal. Rename `.envExample` to `.env` and fill with your credentials.

  * **File**: `src/3_enrich_ips.py`
  * **Lines**:
    ```python
    ABUSEIPDB_API_KEY = "YOUR_KEY_HERE"
    VIRUSTOTAL_API_KEY = "YOUR_KEY_HERE"
    ```

### 2\. Domain Customization

The `src/1_collect_whm_data.py` script uses a regular expression (regex) to focus on emails from a specific domain. If you are analyzing logs from other domains, you will need to adjust this regex.

  * **File**: `src/1_collect_whm_data.py`
  * **Variable**: `regex_email_pr`

-----

## How to Use

With the project configured, usage is simplified to a single command:

1.  **Save the HTML Log**: Place your WHM log file in the `data/00_raw/whm_logs/` folder. The filename must follow the pattern `YY-MM-DD_domain-account.html`.

2.  **Run the Pipeline**: Run `main.py` passing the path to the HTML file as an argument.

    ```bash
    # Example execution:
    python main.py data/00_raw/whm_logs/25-10-30_example-account.html
    ```

3.  **Access the Report**: The pipeline will run, and if everything is successful, you will find the final report in CSV format in the `reports/` folder (e.g., `reports/25-10-30_report_example-account.csv`).

All progress will be displayed in the console and saved to `pipeline.log`.

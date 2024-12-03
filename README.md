# Log File Analyzer

This Python script analyzes web server log files to extract meaningful insights such as request counts per IP address, the most frequently accessed endpoints, and suspicious activities like potential brute force login attempts.

---

## Features

### 1. Count Requests per IP Address
- Parses the log file to count the number of requests made by each IP address.
- Results are sorted in descending order of request counts.

### 2. Identify the Most Frequently Accessed Endpoint
- Analyzes the log file to determine the endpoint (URL or resource path) accessed the most times.
- Displays the most accessed endpoint and its access count.

### 3. Detect Suspicious Activity
- Identifies potential brute force login attempts by:
  - Detecting failed login attempts (e.g., HTTP status code `401` or messages like "Invalid credentials").
  - Flagging IPs with failed login attempts exceeding a configurable threshold (default: 10).
- Displays flagged IPs and their failed login counts.

### 4. Output Results
- Displays results in the terminal in a structured format.
- Saves results to a CSV file (`log_analysis_results.csv`) with separate sections for:
  - **Requests per IP**: `IP Address`, `Request Count`.
  - **Most Accessed Endpoint**: `Endpoint`, `Access Count`.
  - **Suspicious Activity**: `IP Address`, `Failed Login Count`.

---

## Installation

1. Clone this repository or download the script:
   ```bash
   git clone https://github.com/Ayushsinghcse/log-file-analysis
   cd log-file-analyzer

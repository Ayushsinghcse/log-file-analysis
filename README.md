### Log File Analyzer
This Python script analyzes web server log files to extract meaningful insights such as request counts per IP address, the most frequently accessed endpoints, and suspicious activities such as potential brute force login attempts.

### Features
Count Requests per IP Address

### Parses the log file to count the number of requests made by each IP address.
Results are sorted in descending order of request counts.
Identify the Most Frequently Accessed Endpoint

### Analyzes the log file to determine the endpoint (URL or resource path) accessed the most times.
Displays the most accessed endpoint and its access count.
Detect Suspicious Activity

### Identifies potential brute force login attempts by:
Detecting failed login attempts (e.g., HTTP status code 401 or messages like "Invalid credentials").
Flagging IPs with failed login attempts exceeding a configurable threshold (default: 10).
Displays flagged IPs and their failed login counts.
### Output Results

Displays results in the terminal in a structured format.
Saves results to a CSV file (log_analysis_results.csv) with separate sections for:
Requests per IP: IP Address, Request Count.
Most Accessed Endpoint: Endpoint, Access Count.
Suspicious Activity: IP Address, Failed Login Count.
### Installation
Clone this repository or download the script.
Ensure you have Python 3.6 or later installed on your system.
### Usage
1. Prepare the Log File
Save your server log file (e.g., sample.log) in the same directory as the script.

2. Run the Script
Execute the script using Python:

bash
Copy code
python log_analyzer.py
3. View Results
### Results are displayed in the terminal.
A CSV file named log_analysis_results.csv will be generated in the same directory.
Sample Log File Format
The script expects the log file to follow a standard format similar to Apache or NGINX logs. For example:

sql
Copy code
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
Configurations
Threshold for Suspicious Activity
You can modify the threshold for detecting suspicious activity (default: 10 failed login attempts) by editing the following line in the script:

python
Copy code
suspicious_ips = detect_suspicious_ips(failed_logins, threshold=10)

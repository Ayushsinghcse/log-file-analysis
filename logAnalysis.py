import re
import csv
from collections import Counter

def parse_log_file(filepath):
    """
    Parse the log file to extract IP requests, endpoint accesses, and failed login attempts.
    """
    ip_requests = Counter()
    endpoint_accesses = Counter()
    failed_logins = Counter()

    log_pattern = re.compile(
        r'(?P<ip>[\d\.]+) - - .* "(?P<method>\S+) (?P<endpoint>\S+) .*" (?P<status_code>\d+) .*'
    ) #using regular expression

    with open(filepath, 'r') as log:
        for entry in log:
            match = log_pattern.match(entry)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = match.group("status_code")

                # Update counts
                ip_requests[ip] += 1
                endpoint_accesses[endpoint] += 1
                if status == "401":  # Failed login
                    failed_logins[ip] += 1

    return ip_requests, endpoint_accesses, failed_logins

def find_top_endpoint(endpoint_data):
    """ Determine the most frequently accessed endpoint and its count. """
    if not endpoint_data:
        return "None", 0
    return max(endpoint_data.items(), key=lambda x: x[1])

def identify_suspicious_ips(failed_login_data, threshold=10):
    """ Identify IPs with failed logins exceeding the threshold. """
    return {ip: count for ip, count in failed_login_data.items() if count > threshold}

def save_to_csv(ip_data, top_endpoint, suspicious_ips, filename="analysis_results.csv"):
    """ Save analysis results to a CSV file. """
    with open(filename, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write IP request data
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_data.most_common())

        # Write most accessed endpoint data
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(top_endpoint)

        # Write suspicious IPs
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())

def display_results(ip_data, top_endpoint, suspicious_ips):
    """ Display results in a formatted output to the console. """
    print("*** Requests Per IP Address ***")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in ip_data.most_common():
        print(f"{ip:<20} {count}")

    print("\n*** Most Frequently Accessed Endpoint ***")
    print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    print("\n*** Suspicious Activity Detected ***")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

def main():
    log_file = "sample.log"
    ip_data, endpoint_data, failed_logins = parse_log_file(log_file)

    # Find the top endpoint
    top_endpoint = find_top_endpoint(endpoint_data)

    # Identify suspicious activity
    suspicious_ips = identify_suspicious_ips(failed_logins)

    # Display and save results
    display_results(ip_data, top_endpoint, suspicious_ips)
    save_to_csv(ip_data, top_endpoint, suspicious_ips)

if __name__ == "__main__":
    main()

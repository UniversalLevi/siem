#!/usr/bin/env python3
import os
import hashlib
import json
import urllib.request
import urllib.error

# Path to the log file
LOG_FILE = "/var/log/siem_logs/network_logs.json"

# File to store the last sent checksum (hidden file in home directory)
CHECKSUM_FILE = os.path.expanduser("~/.siem_last_sent_checksum")

def calculate_checksum(file_path):
    """Calculate MD5 checksum of the file's content."""
    md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        print(f"Error calculating checksum: {e}")
        return None

def has_been_sent(current_checksum):
    """Check if the current checksum matches the stored checksum."""
    if os.path.exists(CHECKSUM_FILE):
        try:
            with open(CHECKSUM_FILE, "r") as f:
                last_checksum = f.read().strip()
            return last_checksum == current_checksum
        except Exception as e:
            print(f"Error reading checksum file: {e}")
    return False

def store_checksum(checksum):
    """Store the checksum to the marker file."""
    try:
        with open(CHECKSUM_FILE, "w") as f:
            f.write(checksum)
    except Exception as e:
        print(f"Error storing checksum: {e}")

def send_logs(api_url, api_key, json_data):
    """Send the JSON log data to the API via HTTP POST."""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key
    }
    data_bytes = json_data.encode("utf-8")

    print("\n--- DEBUG: Sending this JSON ---")
    print(json_data[:500] + "\n... (truncated)")  # Print the first 500 chars
    print("--- END DEBUG ---\n")

    req = urllib.request.Request(api_url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as response:
            resp_data = response.read().decode("utf-8")
            print(f"Response from API: {resp_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        error_body = e.read().decode("utf-8")
        print("API Error Response:", error_body)
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
    except Exception as e:
        print(f"Error sending logs: {e}")
    return False

def main():
    # Get API URL and API key from user
    api_url = input("Enter the API URL (e.g., http://192.168.74.63:3000/api/logs): ").strip()
    api_key = input("Enter the API key: ").strip()

    # Calculate current file checksum
    current_checksum = calculate_checksum(LOG_FILE)
    if current_checksum is None:
        print("Cannot calculate checksum. Exiting.")
        return

    # Check if logs have already been sent
    if has_been_sent(current_checksum):
        print("Logs have already been sent. No action taken.")
        return

    # Read the JSON file in full
    try:
        with open(LOG_FILE, "r") as f:
            json_content = f.read()
    except Exception as e:
        print(f"Error reading log file: {e}")
        return

    # Optionally, verify that it's valid JSON
    try:
        parsed = json.loads(json_content)
        # Re-dump to preserve the full format in a consistent manner
        json_data = json.dumps(parsed, indent=2)
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return

    # Send logs to the API
    if send_logs(api_url, api_key, json_data):
        print("Logs sent successfully.")
        store_checksum(current_checksum)
    else:
        print("Failed to send logs.")

if __name__ == "__main__":
    main() 
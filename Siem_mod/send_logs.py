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
        "x-api-key": api_key,
        "Accept": "application/json"
    }
    
    # Convert parsed JSON to proper format if needed
    if isinstance(json_data, str):
        try:
            parsed_data = json.loads(json_data)
            # Format data as expected by the API
            payload = {
                "logs": parsed_data
            }
            data_bytes = json.dumps(payload).encode("utf-8")
        except json.JSONDecodeError:
            # If already a string but not valid JSON, wrap it
            payload = {
                "logs": json_data
            }
            data_bytes = json.dumps(payload).encode("utf-8")
    else:
        # If already a Python object
        payload = {
            "logs": json_data
        }
        data_bytes = json.dumps(payload).encode("utf-8")

    print(f"Sending data to {api_url}...")
    req = urllib.request.Request(api_url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as response:
            resp_data = response.read().decode("utf-8")
            print(f"Response from API: {resp_data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        try:
            error_content = e.read().decode('utf-8')
            print(f"Error response content: {error_content}")
        except:
            pass
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
    except Exception as e:
        print(f"Error sending logs: {e}")
    return False

def main(api_url=None, api_key=None):
    """Main function for sending logs.
    
    Args:
        api_url (str, optional): The API URL to send logs to. If None, will prompt user.
        api_key (str, optional): The API key for authentication. If None, will prompt user.
    """
    # Get API URL and API key from user if not provided
    if not api_url:
        api_url = input("Enter the API URL (e.g., http://192.168.74.63:3000/api/logs): ").strip()
    
    if not api_key:
        api_key = input("Enter the API key: ").strip()

    # Calculate current file checksum
    current_checksum = calculate_checksum(LOG_FILE)
    if current_checksum is None:
        print("Cannot calculate checksum. Exiting.")
        return False

    # Check if logs have already been sent
    if has_been_sent(current_checksum):
        print("Logs have already been sent. No action taken.")
        return True

    # Read the JSON file in full
    try:
        with open(LOG_FILE, "r") as f:
            json_content = f.read()
    except Exception as e:
        print(f"Error reading log file: {e}")
        return False

    # Optionally, verify that it's valid JSON
    try:
        parsed = json.loads(json_content)
        # Re-dump to preserve the full format in a consistent manner
        json_data = json.dumps(parsed, indent=2)
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return False

    # Send logs to the API
    if send_logs(api_url, api_key, parsed):
        print("Logs sent successfully.")
        store_checksum(current_checksum)
        return True
    else:
        print("Failed to send logs.")
        return False

if __name__ == "__main__":
    main()

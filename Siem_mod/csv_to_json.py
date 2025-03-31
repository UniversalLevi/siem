import csv
import json
import os
from collections import defaultdict

# Use absolute paths for logs
SIEM_LOGS_DIR = "/var/log/siem_logs"

# Use absolute paths based on the log directory
CSV_FILE = os.path.join(SIEM_LOGS_DIR, "network_logs.csv")
JSON_FILE = os.path.join(SIEM_LOGS_DIR, "network_logs.json")

def convert_csv_to_json():
    print(f"Converting CSV to JSON... (Looking for CSV at: {CSV_FILE})")  # Added logging
    """Convert CSV logs to JSON with all fields included in interactions."""
    interactions = defaultdict(lambda: {"interactions": [], "total_duration": 0.0})
    
    # Check if CSV file exists
    if not os.path.exists(CSV_FILE):
        print(f"Error: CSV file not found at {CSV_FILE}")
        return False
    
    # Read CSV and group by src_ip and dst_ip
    with open(CSV_FILE, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            src_ip = row["src_ip"]
            dst_ip = row["dst_ip"]
            key = (src_ip, dst_ip)
            duration = float(row["duration"])
            
            # Append the full row to interactions
            interactions[key]["interactions"].append(row)
            interactions[key]["total_duration"] += duration
            interactions[key]["src_ip"] = src_ip
            interactions[key]["dst_ip"] = dst_ip

    # Format JSON output with all fields
    json_data = [
        {
            "src_ip": data["src_ip"],
            "dst_ip": data["dst_ip"],
            "total_duration": round(data["total_duration"], 2),
            "interactions": [
                {
                    "timestamp": interaction["timestamp"],
                    "duration": float(interaction["duration"]),
                    "protocol_type": interaction["protocol_type"],
                    "src_ip": interaction["src_ip"],
                    "src_port": int(interaction["src_port"]),
                    "dst_ip": interaction["dst_ip"],
                    "dst_port": int(interaction["dst_port"]),
                    "service": interaction["service"],
                    "flag": interaction["flag"],
                    "src_bytes": int(interaction["src_bytes"]),
                    "dst_bytes": int(interaction["dst_bytes"]),
                    "land": int(interaction["land"]),
                    "wrong_fragment": int(interaction["wrong_fragment"]),
                    "urgent": int(interaction["urgent"]),
                    "hot": int(interaction["hot"]),
                    "num_failed_logins": int(interaction["num_failed_logins"]),
                    "logged_in": int(interaction["logged_in"]),
                    "num_compromised": int(interaction["num_compromised"]),
                    "root_shell": int(interaction["root_shell"]),
                    "su_attempted": int(interaction["su_attempted"]),
                    "num_root": int(interaction["num_root"]),
                    "num_file_creations": int(interaction["num_file_creations"]),
                    "num_shells": int(interaction["num_shells"]),
                    "num_access_files": int(interaction["num_access_files"]),
                    "num_outbound_cmds": int(interaction["num_outbound_cmds"]),
                    "is_host_login": int(interaction["is_host_login"]),
                    "is_guest_login": int(interaction["is_guest_login"]),
                    "count": int(interaction["count"]),
                    "srv_count": int(interaction["srv_count"]),
                    "serror_rate": float(interaction["serror_rate"]),
                    "srv_serror_rate": float(interaction["srv_serror_rate"]),
                    "rerror_rate": float(interaction["rerror_rate"]),
                    "srv_rerror_rate": float(interaction["srv_rerror_rate"]),
                    "same_srv_rate": float(interaction["same_srv_rate"]),
                    "diff_srv_rate": float(interaction["diff_srv_rate"]),
                    "srv_diff_host_rate": float(interaction["srv_diff_host_rate"]),
                    "dst_host_count": int(interaction["dst_host_count"]),
                    "dst_host_srv_count": int(interaction["dst_host_srv_count"]),
                    "dst_host_same_srv_rate": float(interaction["dst_host_same_srv_rate"]),
                    "dst_host_diff_srv_rate": float(interaction["dst_host_diff_srv_rate"]),
                    "dst_host_same_src_port_rate": float(interaction["dst_host_same_src_port_rate"]),
                    "dst_host_srv_diff_host_rate": float(interaction["dst_host_srv_diff_host_rate"]),
                    "dst_host_serror_rate": float(interaction["dst_host_serror_rate"]),
                    "dst_host_srv_serror_rate": float(interaction["dst_host_srv_serror_rate"]),
                    "dst_host_rerror_rate": float(interaction["dst_host_rerror_rate"]),
                    "dst_host_srv_rerror_rate": float(interaction["dst_host_srv_rerror_rate"]),
                    "attack_type": interaction["attack_type"],
                    "description": interaction["description"]
                }
                for interaction in data["interactions"]
            ]
        }
        for key, data in interactions.items()
    ]

    # Write to JSON file
    with open(JSON_FILE, "w") as jsonfile:
        json.dump(json_data, jsonfile, indent=2)
    
    print(f"Converted {sum(len(data['interactions']) for data in json_data)} interactions from CSV to JSON.")
    print(f"JSON file saved to: {JSON_FILE}")
    return True

if __name__ == "__main__":
    convert_csv_to_json()


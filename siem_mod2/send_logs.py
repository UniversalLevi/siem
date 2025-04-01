import time
import json
import os
import requests
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Path to the logs file
SIEM_LOGS_DIR = "/var/log/siem_logs"
JSON_FILE = os.path.join(SIEM_LOGS_DIR, "network_logs.json")

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, api_endpoint, api_key):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        
    def on_modified(self, event):
        if event.src_path == JSON_FILE:
            print(f"Change detected in {JSON_FILE}, sending to API...")
            self.send_logs_to_api()
    
    def send_logs_to_api(self):
        try:
            # Wait a moment to ensure the file writing is complete
            time.sleep(1)
            
            # Read the JSON file
            with open(JSON_FILE, 'r') as file:
                log_data = json.load(file)
            
            # Send the data to the API
            headers = {
                'Content-Type': 'application/json'
            }
            
            # Add authorization header if API key is provided
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
                
            response = requests.post(self.api_endpoint, json=log_data, headers=headers)
            
            if response.status_code == 200:
                print("Successfully sent log data to API")
            else:
                print(f"Failed to send data: {response.status_code}, {response.text}")
                
        except Exception as e:
            print(f"Error sending logs to API: {str(e)}")

def start_monitoring(api_endpoint, api_key):
    event_handler = LogFileHandler(api_endpoint, api_key)
    observer = Observer()
    
    # Monitor the directory containing the JSON file
    observer.schedule(event_handler, os.path.dirname(JSON_FILE), recursive=False)
    observer.start()
    
    print(f"Started monitoring {JSON_FILE} for changes")
    print(f"Will send data to API at: {api_endpoint}")
    
    try:
        # Run indefinitely
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def parse_arguments():
    parser = argparse.ArgumentParser(description='Send SIEM logs to API endpoint')
    parser.add_argument('--api_endpoint', required=True, help='API endpoint URL')
    parser.add_argument('--api_key', default='', help='API key for authentication')
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command line arguments
    args = parse_arguments()
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)
    
    print(f"Logs directory: {SIEM_LOGS_DIR}")
    print(f"Watching for changes to: {JSON_FILE}")
    print(f"Will send data to API at: {args.api_endpoint}")
    
    # If the file exists on startup, send it immediately
    if os.path.exists(JSON_FILE):
        print(f"Found existing log file, sending initial data...")
        handler = LogFileHandler(args.api_endpoint, args.api_key)
        handler.send_logs_to_api()
    else:
        print(f"No log file found at {JSON_FILE}. Will wait for it to be created.")
    
    # Start monitoring for changes
    start_monitoring(args.api_endpoint, args.api_key) 
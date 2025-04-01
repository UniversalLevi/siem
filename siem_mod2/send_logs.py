import time
import json
import os
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration - replace with your actual API endpoint
API_ENDPOINT = "https://your-server.com/api/siem-data"
API_KEY = "your-api-key"  # If your API requires authentication

# Path to the logs file
SIEM_LOGS_DIR = "/var/log/siem_logs"
JSON_FILE = os.path.join(SIEM_LOGS_DIR, "network_logs.json")

class LogFileHandler(FileSystemEventHandler):
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
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {API_KEY}'  # If your API uses bearer token
            }
            response = requests.post(API_ENDPOINT, json=log_data, headers=headers)
            
            if response.status_code == 200:
                print("Successfully sent log data to API")
            else:
                print(f"Failed to send data: {response.status_code}, {response.text}")
                
        except Exception as e:
            print(f"Error sending logs to API: {str(e)}")

def start_monitoring():
    event_handler = LogFileHandler()
    observer = Observer()
    
    # Monitor the directory containing the JSON file
    observer.schedule(event_handler, os.path.dirname(JSON_FILE), recursive=False)
    observer.start()
    
    print(f"Started monitoring {JSON_FILE} for changes")
    
    try:
        # Run indefinitely
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Ensure the directory exists
    os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)
    
    # If the file exists on startup, send it immediately
    if os.path.exists(JSON_FILE):
        handler = LogFileHandler()
        handler.send_logs_to_api()
    
    # Start monitoring for changes
    start_monitoring() 
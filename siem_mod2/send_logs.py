import time
import json
import os
import sys
import logging
import urllib3
import argparse
import pyinotify  # Linux-specific file system monitoring

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.expanduser('~/send_logs.log'))
    ]
)
logger = logging.getLogger('send_logs')

# Path to the logs file
SIEM_LOGS_DIR = "/var/log/siem_logs"
JSON_FILE = os.path.join(SIEM_LOGS_DIR, "network_logs.json")

# Setup urllib3 connection pool
http = urllib3.PoolManager(timeout=10.0, retries=urllib3.Retry(3, redirect=2))

# Check if running with sudo permissions
def check_sudo():
    """Check if the script is running with sudo privileges"""
    if os.geteuid() != 0:
        logger.warning("This script may require sudo privileges to access certain log files")
        logger.warning("Consider running with sudo if you encounter permission errors")
        return False
    return True

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, api_endpoint, api_key):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        
    def process_IN_MODIFY(self, event):
        if event.pathname == JSON_FILE:
            logger.info(f"Change detected in {JSON_FILE}, sending to API...")
            self.send_logs_to_api()
            
    def process_IN_CREATE(self, event):
        if event.pathname == JSON_FILE:
            logger.info(f"File created: {JSON_FILE}, sending to API...")
            self.send_logs_to_api()
    
    def send_logs_to_api(self):
        try:
            # Wait a moment to ensure the file writing is complete
            time.sleep(1)
            
            # Check if file exists
            if not os.path.exists(JSON_FILE):
                logger.error(f"JSON file not found at: {JSON_FILE}")
                return False
                
            try:
                # Read the JSON file
                with open(JSON_FILE, 'r') as file:
                    log_data = json.load(file)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON: {str(e)}")
                return False
            except PermissionError:
                logger.error(f"Permission denied when reading {JSON_FILE}. Try running with sudo.")
                return False
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json'
            }
            
            # Add authorization header if API key is provided
            if self.api_key:
                # Handle different API key formats
                if self.api_key.startswith('Bearer '):
                    headers['Authorization'] = self.api_key
                elif self.api_key.lower().startswith('basic '):
                    headers['Authorization'] = self.api_key
                elif ':' in self.api_key:  # Basic auth with username:password format
                    import base64
                    auth_str = base64.b64encode(self.api_key.encode('utf-8')).decode('utf-8')
                    headers['Authorization'] = f'Basic {auth_str}'
                else:
                    headers['Authorization'] = f'Bearer {self.api_key}'
                    
                logger.debug(f"Using authorization header: {headers['Authorization'][:10]}...")
            
            try:
                # Send data using urllib3
                encoded_data = json.dumps(log_data).encode('utf-8')
                
                # Log request information (without sensitive data)
                logger.info(f"Sending POST request to {self.api_endpoint} with {len(encoded_data)} bytes of data")
                
                response = http.request(
                    'POST',
                    self.api_endpoint,
                    body=encoded_data,
                    headers=headers
                )
                
                # Check for success (200 OK) or other successful status codes (201, 202, 204)
                if response.status >= 200 and response.status < 300:
                    logger.info(f"Successfully sent log data to API (Status: {response.status})")
                    return True
                else:
                    try:
                        # Try to parse the error response
                        error_data = json.loads(response.data.decode('utf-8'))
                        error_message = error_data.get('message', error_data.get('error', 'Unknown error'))
                        logger.error(f"API error: {error_message} (Status: {response.status})")
                    except:
                        # If can't parse JSON, use raw response
                        logger.error(f"Failed to send data: {response.status}, {response.data.decode('utf-8')[:200]}")
                    return False
            except urllib3.exceptions.NewConnectionError:
                logger.error(f"Connection error when connecting to {self.api_endpoint}. Check network connectivity.")
                return False
            except urllib3.exceptions.TimeoutError:
                logger.error("API request timed out. Server might be busy or unreachable.")
                return False
            except Exception as e:
                logger.error(f"Request error: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending logs to API: {str(e)}", exc_info=True)
            return False

def start_monitoring(api_endpoint, api_key):
    try:
        # Check if the directory exists, create it if it doesn't
        os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)
        
        # Setup pyinotify
        wm = pyinotify.WatchManager()
        handler = EventHandler(api_endpoint, api_key)
        notifier = pyinotify.Notifier(wm, handler)
        
        # Watch the directory for CREATE and MODIFY events
        mask = pyinotify.IN_MODIFY | pyinotify.IN_CREATE
        wm.add_watch(os.path.dirname(JSON_FILE), mask)
        
        logger.info(f"Started monitoring {JSON_FILE} for changes")
        logger.info(f"Will send data to API at: {api_endpoint}")
        
        # Process events until keyboard interrupt
        try:
            notifier.loop()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            notifier.stop()
            
        return True
    except PermissionError:
        logger.error(f"Permission denied when accessing {os.path.dirname(JSON_FILE)}. Try running with sudo.")
        return False
    except Exception as e:
        logger.error(f"Error in monitoring: {str(e)}", exc_info=True)
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description='Send SIEM logs to API endpoint')
    parser.add_argument('--api_endpoint', 
                      default="http://192.168.1.116:3000/api/logs",
                      help='API endpoint URL (default: http://192.168.1.116:3000/api/logs)')
    parser.add_argument('--api_key', 
                      default='your-secure-api-key', 
                      help='API key for authentication (default: your-secure-api-key)')
    return parser.parse_args()

if __name__ == "__main__":
    # Check for sudo permissions
    is_sudo = check_sudo()
    
    # Parse command line arguments
    try:
        args = parse_arguments()
        logger.info(f"Using API endpoint: {args.api_endpoint}")
        logger.info(f"Using API key: {'*****' if args.api_key else 'None'}")
    except Exception as e:
        logger.error(f"Error parsing arguments: {str(e)}")
        sys.exit(1)
    
    # Validate API endpoint
    if not args.api_endpoint.startswith(('http://', 'https://')):
        args.api_endpoint = 'http://' + args.api_endpoint
        logger.info(f"Modified API endpoint to include protocol: {args.api_endpoint}")
        
    # Validate API endpoint is reachable
    try:
        test_response = http.request('HEAD', args.api_endpoint, timeout=2.0)
        logger.info(f"API endpoint is reachable (Status: {test_response.status})")
    except Exception as e:
        logger.warning(f"API endpoint may not be reachable: {str(e)}")
        logger.warning("Will continue and retry when sending logs")
    
    # Ensure the directory exists
    try:
        os.makedirs(os.path.dirname(JSON_FILE), exist_ok=True)
        logger.info(f"Logs directory: {SIEM_LOGS_DIR}")
    except PermissionError:
        logger.error(f"Permission denied when creating {SIEM_LOGS_DIR}. Try running with sudo.")
        sys.exit(1)
    
    logger.info(f"Watching for changes to: {JSON_FILE}")
    logger.info(f"Will send data to API at: {args.api_endpoint}")
    
    # If the file exists on startup, send it immediately
    if os.path.exists(JSON_FILE):
        logger.info(f"Found existing log file, sending initial data...")
        handler = EventHandler(args.api_endpoint, args.api_key)
        if handler.send_logs_to_api():
            logger.info("Successfully sent initial data")
        else:
            logger.warning("Failed to send initial data")
    else:
        logger.info(f"No log file found at {JSON_FILE}. Will wait for it to be created.")
    
    # Start monitoring for changes
    if not start_monitoring(args.api_endpoint, args.api_key):
        sys.exit(1) 
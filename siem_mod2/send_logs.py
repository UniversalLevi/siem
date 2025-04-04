import time
import json
import os
import sys
import logging
import urllib3
import argparse
import pyinotify  # Linux-specific file system monitoring
import grp
import pwd
import stat

# Setup logging
log_dir = os.path.expanduser('~/.siem')
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(log_dir, 'send_logs.log'))
    ]
)
logger = logging.getLogger('send_logs')

# Path to the logs file - configurable
DEFAULT_SIEM_LOGS_DIR = "/var/log/siem_logs"
ALT_LOGS_DIR = os.path.expanduser("~/siem_logs")

# Setup urllib3 connection pool
http = urllib3.PoolManager(timeout=10.0, retries=urllib3.Retry(3, redirect=2))

def check_sudo():
    """Check if the script is running with sudo privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows doesn't have geteuid
        return False

def setup_log_access(logs_dir=None):
    """Setup appropriate log directory and permissions"""
    if logs_dir is None:
        logs_dir = DEFAULT_SIEM_LOGS_DIR
        
    is_sudo = check_sudo()
    
    # Try the specified directory first
    if os.path.exists(logs_dir):
        if os.access(logs_dir, os.R_OK):
            logger.info(f"Using existing logs directory: {logs_dir}")
            return logs_dir
            
    # If running with sudo, try to set up the directory with proper permissions
    if is_sudo:
        try:
            os.makedirs(logs_dir, exist_ok=True)
            
            # Get the user who invoked sudo
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                # Get user and group IDs
                uid = pwd.getpwnam(sudo_user).pw_uid
                # Get group ID more safely - try user's primary group first, then fall back to group 'users'
                try:
                    gid = pwd.getpwnam(sudo_user).pw_gid  # Get primary group ID from password database
                except Exception:
                    try:
                        gid = grp.getgrnam('users').gr_gid  # Common fallback group on most Linux systems
                    except Exception:
                        gid = -1  # Keep current group if can't determine
                
                # Change ownership of logs directory
                os.chown(logs_dir, uid, gid)
                
                # Set permissions to rwxrwxr-- (more permissive for group)
                os.chmod(logs_dir, 0o774)
                
                logger.info(f"Set permissions on {logs_dir} for user {sudo_user}")
            else:
                # If can't determine sudo user, set permissions to allow group access
                os.chmod(logs_dir, 0o774)
                
            return logs_dir
        except Exception as e:
            logger.warning(f"Failed to set up directory {logs_dir}: {e}")
    
    # Fall back to home directory if main directory is not accessible
    try:
        os.makedirs(ALT_LOGS_DIR, exist_ok=True)
        logger.warning(f"Using alternative log directory: {ALT_LOGS_DIR}")
        return ALT_LOGS_DIR
    except Exception as e:
        logger.error(f"Failed to create alternative log directory: {e}")
        raise RuntimeError(f"Cannot access or create any log directory")

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, api_endpoint, api_key, json_file):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.json_file = json_file
        
    def process_IN_MODIFY(self, event):
        if event.pathname == self.json_file:
            logger.info(f"Change detected in {self.json_file}, sending to API...")
            self.send_logs_to_api()
            
    def process_IN_CREATE(self, event):
        if event.pathname == self.json_file:
            logger.info(f"File created: {self.json_file}, sending to API...")
            self.send_logs_to_api()
    
    def send_logs_to_api(self):
        try:
            # Wait a moment to ensure the file writing is complete
            time.sleep(1)
            
            # Check if file exists
            if not os.path.exists(self.json_file):
                logger.error(f"JSON file not found at: {self.json_file}")
                return False
                
            try:
                # Read the JSON file
                with open(self.json_file, 'r') as file:
                    log_data = json.load(file)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON: {str(e)}")
                return False
            except PermissionError:
                logger.error(f"Permission denied when reading {self.json_file}")
                return False
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json',
                'X-API-Key': 'your-secure-api-key'  # Always use this specific value
            }
            
            # Log the header (partially)
            logger.debug("Using X-API-Key header with default secure key")
            
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

def create_systemd_service(script_path, api_endpoint, api_key, logs_dir):
    """Create a systemd service file to run the script at startup without sudo"""
    if not check_sudo():
        logger.error("Creating a systemd service requires sudo privileges")
        return False
        
    try:
        # Determine the user who is running the sudo command
        user = os.environ.get('SUDO_USER', os.getlogin())
        
        service_content = f"""[Unit]
Description=SIEM Logs Sender Service
After=network.target

[Service]
Type=simple
User={user}
ExecStart={sys.executable} {script_path} --api_endpoint "{api_endpoint}" --logs-dir "{logs_dir}"
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        
        service_path = "/etc/systemd/system/siem-logs-sender.service"
        with open(service_path, 'w') as f:
            f.write(service_content)
            
        logger.info(f"Created systemd service at {service_path}")
        logger.info("To enable the service, run:")
        logger.info("  sudo systemctl daemon-reload")
        logger.info("  sudo systemctl enable siem-logs-sender.service")
        logger.info("  sudo systemctl start siem-logs-sender.service")
        
        return True
    except Exception as e:
        logger.error(f"Failed to create systemd service: {e}")
        return False

def start_monitoring(api_endpoint, api_key, logs_dir):
    """Start monitoring the JSON file for changes"""
    json_file = os.path.join(logs_dir, "network_logs.json")
    
    try:
        # Setup pyinotify
        wm = pyinotify.WatchManager()
        handler = EventHandler(api_endpoint, api_key, json_file)
        notifier = pyinotify.Notifier(wm, handler)
        
        # Watch the directory for CREATE and MODIFY events
        logger.info(f"Adding watch for directory: {logs_dir}")
        mask = pyinotify.IN_MODIFY | pyinotify.IN_CREATE
        wm.add_watch(logs_dir, mask)
        
        logger.info(f"Started monitoring {json_file} for changes")
        logger.info(f"Will send data to API at: {api_endpoint}")
        
        # If the file exists on startup, send it immediately
        if os.path.exists(json_file):
            logger.info(f"Found existing log file, sending initial data...")
            if handler.send_logs_to_api():
                logger.info("Successfully sent initial data")
            else:
                logger.warning("Failed to send initial data")
        else:
            logger.info(f"No log file found at {json_file}. Will wait for it to be created.")
        
        # Process events until keyboard interrupt
        try:
            notifier.loop()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            notifier.stop()
            
        return True
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        return False
    except Exception as e:
        logger.error(f"Error in monitoring: {e}", exc_info=True)
        return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Send SIEM logs to API endpoint')
    parser.add_argument('--api_endpoint', 
                      default="http://192.168.1.116:3000/api/logs",
                      help='API endpoint URL (default: http://192.168.1.116:3000/api/logs)')
    parser.add_argument('--api_key', 
                      help='API key for authentication (deprecated, X-API-Key header is hardcoded)')
    parser.add_argument('--logs-dir', '--logs_dir',  # Accept both formats for compatibility
                      help='Custom logs directory path (default: /var/log/siem_logs or ~/siem_logs)')
    parser.add_argument('--create-service', action='store_true',
                      help='Create systemd service to run this script (requires sudo)')
    parser.add_argument('--test', action='store_true',
                      help='Test mode - verify access and exit')
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command line arguments
    try:
        args = parse_arguments()
    except Exception as e:
        logger.error(f"Error parsing arguments: {e}")
        sys.exit(1)
        
    # Log initial settings
    logger.info(f"Send Logs script starting up")
    logger.info(f"API endpoint: {args.api_endpoint}")
    
    # Validate API endpoint
    if not args.api_endpoint.startswith(('http://', 'https://')):
        args.api_endpoint = 'http://' + args.api_endpoint
        logger.info(f"Modified API endpoint to include protocol: {args.api_endpoint}")
    
    # Setup appropriate log directory
    try:
        logs_dir = setup_log_access(args.logs_dir)
        logger.info(f"Using logs directory: {logs_dir}")
    except Exception as e:
        logger.error(f"Failed to setup log directory: {e}")
        sys.exit(1)
    
    # Create systemd service if requested
    if args.create_service:
        if create_systemd_service(os.path.abspath(__file__), args.api_endpoint, args.api_key, logs_dir):
            logger.info("Systemd service created successfully")
            sys.exit(0)
        else:
            logger.error("Failed to create systemd service")
            sys.exit(1)
            
    # Test mode - just verify access and exit
    if args.test:
        json_file = os.path.join(logs_dir, "network_logs.json")
        
        logger.info(f"Testing log access:")
        logger.info(f"  Logs dir: {logs_dir}")
        logger.info(f"  JSON file path: {json_file}")
        logger.info(f"  API endpoint: {args.api_endpoint}")
        
        # Check dir access
        logger.info(f"  Directory exists: {os.path.exists(logs_dir)}")
        logger.info(f"  Directory readable: {os.access(logs_dir, os.R_OK)}")
        logger.info(f"  Directory writable: {os.access(logs_dir, os.W_OK)}")
        
        # Check file access if it exists
        if os.path.exists(json_file):
            logger.info(f"  JSON file exists: Yes")
            logger.info(f"  JSON file readable: {os.access(json_file, os.R_OK)}")
        else:
            logger.info(f"  JSON file exists: No")
            
        # Test API endpoint
        try:
            response = http.request('HEAD', args.api_endpoint, timeout=2.0)
            logger.info(f"  API endpoint reachable: Yes (Status: {response.status})")
        except Exception as e:
            logger.info(f"  API endpoint reachable: No ({str(e)})")
            
        logger.info("Test complete. Exiting.")
        sys.exit(0)
            
    # Start monitoring
    start_monitoring(args.api_endpoint, args.api_key, logs_dir) 
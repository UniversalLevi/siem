import subprocess 
import threading
import time
import os
import csv_to_json  # Ensure this file is in the same directory
from siem import init_csv, process_packet
from utils import start_thread, console_alert
from greeting import display_greeting
from scapy.all import sniff
import json
import sys
from check_security import *
from enforce_security import *

# Get the script's directory and log directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SIEM_LOGS_DIR = "/var/log/siem_logs"

# Create logs directory if it doesn't exist
os.makedirs(SIEM_LOGS_DIR, exist_ok=True)

# Load settings from configuration file
CONFIG_FILE = os.path.join(SCRIPT_DIR, "settings.conf")

def load_config():
    """Load settings from the config file"""
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    return config

def display_menu():
    """Display the main menu"""
    print("\n=== Security Management Tool ===")
    print("1. Check Security Status")
    print("2. Enforce Security Measures")
    print("3. Exit")
    return input("Select an option (1-3): ")

def run_security_checks(config, silent=False):
    """Run security checks based on config settings"""
    if not silent:
        print("\nRunning security checks...")
    checks = {
        "Firewall Enabled": check_firewall() if config.get("FIREWALL_ENABLED") == "on" else "Skipped",
        "Antivirus Installed": check_antivirus() if config.get("ANTIVIRUS_INSTALLED") == "on" else "Skipped",
        "OS and Software Patches Up-to-date": check_updates() if config.get("PATCHES") == "up-to-date" else "Skipped",
        "SSH Secured": check_ssh_config() if config.get("SSH_CONFIG") == "secure" else "Skipped",
        "Secure Boot Enabled": check_secure_boot() if config.get("SECURE_BOOT") == "enabled" else "Skipped",
        "Strong Password Policy": check_password_policy() if config.get("PASSWORD_POLICY") == "strict" else "Skipped",
        "Disk Encryption Enabled": check_disk_encryption() if config.get("DISK_ENCRYPTION") == "enabled" else "Skipped",
        "Multi-Factor Authentication Enabled": check_mfa() if config.get("MFA") == "enabled" else "Skipped",
        "Audit Logging Enabled": check_logging() if config.get("AUDIT_LOGGING") == "enabled" else "Skipped",
        "RDP Disabled": check_rdp() if config.get("RDP_ACCESS") == "secure" else "Skipped",
    }

    # Save results to a file with absolute path
    security_report_path = os.path.join(SIEM_LOGS_DIR, "security_report.json")
    with open(security_report_path, "w") as file:
        json.dump(checks, file, indent=4)
    
    if not silent:
        print("\nSecurity check completed successfully!")
        print(f"Report saved as '{security_report_path}'")
    else:
        print(f"Security checks completed silently. Report saved as '{security_report_path}'.")

def run_security_enforcement(config, silent=False):
    """Run security enforcement based on config settings"""
    if not silent:
        print("\nRunning security enforcement...")
    
    if config.get("FIREWALL_ENABLED") == "on":
        enforce_firewall()
    if config.get("ANTIVIRUS_INSTALLED") == "on":
        enforce_antivirus()
    if config.get("PATCHES") == "up-to-date":
        enforce_auto_updates()
    if config.get("SSH_CONFIG") == "secure":
        enforce_ssh_security()
    if config.get("DISK_ENCRYPTION") == "enabled":
        enforce_disk_encryption()
    if config.get("BACKUP_RECOVERY") == "enabled":
        enforce_backups()
    # Add more enforcement calls based on config as needed
    
    if not silent:
        print("\nSecurity enforcement completed successfully!")
    else:
        print("Security enforcement completed silently.")

def packet_sniffer():
    """Sniff packets and process them."""
    console_alert("Starting packet sniffer...", "INFO")
    sniff(prn=process_packet, filter="ip or icmp", store=0)

def convert_csv_to_json():
    """Run the csv_to_json.py script to convert CSV to JSON."""
    try:
        script_path = os.path.join(SCRIPT_DIR, "csv_to_json.py")
        result = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
        if result.returncode == 0:
            console_alert("Successfully converted CSV to JSON", "INFO")
        else:
            console_alert(f"Error running csv_to_json.py: {result.stderr}", "ERROR")
    except Exception as e:
        console_alert(f"Failed to run csv_to_json.py: {str(e)}", "ERROR")
        
        # Fallback to direct module call
        try:
            console_alert("Trying direct module call...", "INFO")
            success = csv_to_json.convert_csv_to_json()
            if success:
                console_alert("Successfully converted CSV to JSON using direct module call", "INFO")
            else:
                console_alert("Failed to convert CSV to JSON using direct module call", "ERROR")
        except Exception as e2:
            console_alert(f"Both conversion methods failed: {str(e2)}", "ERROR")

def main():
    """Main function to start SIEM."""
    try:
        display_greeting()
        init_csv()
        config = load_config()
        
        if not config:
            console_alert("Warning: No configuration loaded. Using default settings.", "WARNING")
            config = {
                "FIREWALL_ENABLED": "on",
                "ANTIVIRUS_INSTALLED": "on",
                "PATCHES": "up-to-date",
                "SSH_CONFIG": "secure",
                "DISK_ENCRYPTION": "enabled",
                "BACKUP_RECOVERY": "enabled"
            }

        # Start packet sniffer in a separate thread
        sniffer_thread = start_thread(packet_sniffer)
        
        # Convert CSV to JSON at startup
        csv_to_json.convert_csv_to_json()
        
        # Instead of interactive menu, automatically run security checks and enforcement
        console_alert("Automatically running security checks...", "INFO")
        run_security_checks(config, silent=False)
        
        console_alert("Automatically running security enforcement...", "INFO")
        run_security_enforcement(config, silent=False)
        
        # Keep the main thread running
        console_alert("SIEM is now running in monitoring mode. Press Ctrl+C to exit.", "INFO")
        try:
            # Use an infinite loop to keep the main thread alive
            while True:
                time.sleep(60)  # Sleep for 60 seconds
                # Periodically run checks and enforcement
                run_security_checks(config, silent=True)
                run_security_enforcement(config, silent=True)
                # Convert CSV to JSON periodically
                convert_csv_to_json()
                
        except KeyboardInterrupt:
            console_alert("Shutting down SIEM...", "INFO")
            # Run csv_to_json.py on shutdown
            convert_csv_to_json()
            console_alert("SIEM shutdown complete.", "INFO")
                
    except Exception as e:
        console_alert(f"Fatal error: {str(e)}", "ERROR")
        sys.exit(1)
    finally:
        # Ensure CSV to JSON conversion happens on any exit
        try:
            convert_csv_to_json()
        except:
            pass

if __name__ == "__main__":
    main()


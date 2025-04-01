from datetime import datetime

def display_greeting():
    """Display a greeting message when SIEM starts."""
    print("=====================================")
    print("Welcome to SIEM - Network Monitoring")
    print(f"Started at: {datetime.now()}")
    print("Developed by: Octopyder Services")
    print("=====================================")
    print("\n[INFO] Network traffic monitoring is active in the background")
    print("[INFO] All logs will be saved in /var/log/siem_logs directory")

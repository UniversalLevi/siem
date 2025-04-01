import os
import subprocess
import json

# Get the script's directory and use absolute paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "settings.conf")

def check_firewall():
    """Check if the firewall is enabled"""
    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        return "active" in result.stdout.lower()
    except:
        return False

def check_antivirus():
    """Check if an antivirus is installed"""
    antivirus_tools = ["clamav", "chkrootkit", "rkhunter"]
    installed = any(os.system(f"which {tool} > /dev/null 2>&1") == 0 for tool in antivirus_tools)
    return installed

def check_updates():
    """Check if updates are available"""
    try:
        result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
        return "upgradable" in result.stdout.lower()
    except:
        return False

def check_ssh_config():
    """Check if SSH is secured (password authentication disabled, key-based enabled)"""
    try:
        with open("/etc/ssh/sshd_config", "r") as file:
            config = file.read()
        return "PasswordAuthentication no" in config and "PermitRootLogin no" in config
    except:
        return False

def check_secure_boot():
    """Check if Secure Boot is enabled"""
    return os.path.exists("/sys/firmware/efi")  # If the directory exists, it's likely enabled

def check_password_policy():
    """Check password policy (shadow file min length)"""
    try:
        with open("/etc/security/pwquality.conf", "r") as file:
            for line in file:
                if "minlen" in line and int(line.split("=")[1]) >= 12:
                    return True
    except:
        return False
    return False

def check_disk_encryption():
    """Check if disk encryption (LUKS) is enabled"""
    try:
        result = subprocess.run(["lsblk", "-o", "NAME,MOUNTPOINT,TYPE"], capture_output=True, text=True)
        return "crypt" in result.stdout.lower()
    except:
        return False

def check_mfa():
    """Check if MFA is enabled (Google Authenticator or similar)"""
    return os.path.exists("/etc/google-authenticator")  # Common MFA indicator

def check_logging():
    """Check if audit logging is enabled"""
    return os.path.exists("/var/log/audit/")

def check_rdp():
    """Check if RDP is disabled (Linux usually doesn't use it)"""
    result = os.system("systemctl is-active xrdp > /dev/null 2>&1")
    return result != 0  # If xrdp is inactive, return True

def run_security_checks():
    """Run all security checks and save results."""
    try:
        checks = {
            "Firewall Enabled": check_firewall(),
            "Antivirus Installed": check_antivirus(),
            "OS and Software Patches Up-to-date": check_updates(),
            "SSH Secured": check_ssh_config(),
            "Secure Boot Enabled": check_secure_boot(),
            "Strong Password Policy": check_password_policy(),
            "Disk Encryption Enabled": check_disk_encryption(),
            "Multi-Factor Authentication Enabled": check_mfa(),
            "Audit Logging Enabled": check_logging(),
            "RDP Disabled": check_rdp(),
        }
        
        # Save results to a file with absolute path
        security_report_path = os.path.join(SCRIPT_DIR, "security_report.json")
        try:
            with open(security_report_path, "w") as file:
                json.dump(checks, file, indent=4)
            print(f"\nReport saved as '{security_report_path}'.")
            return checks
        except Exception as e:
            print(f"Error saving security report: {str(e)}")
            return None
            
    except Exception as e:
        print(f"Error running security checks: {str(e)}")
        return None

if __name__ == "__main__":
    run_security_checks()

import os
import subprocess
import logging
import sys

# Get script directory and use absolute paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "security_enforcement.log")

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Run shell commands safely
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        logging.error(f"Error executing {command}: {e}")
        return None, 1

# Ensure UFW is installed and enabled
def enforce_firewall():
    stdout, _ = run_command("command -v ufw")
    if not stdout:
        logging.info("Installing UFW...")
        run_command("sudo apt install -y ufw")
    
    stdout, _ = run_command("sudo ufw status")
    if "inactive" in stdout:
        logging.info("Enabling UFW...")
        run_command("echo 'y' | sudo ufw enable")

# Ensure Anti-virus is installed (ClamAV for Linux)
def enforce_antivirus():
    stdout, _ = run_command("command -v clamscan")
    if not stdout:
        logging.info("Installing ClamAV...")
        run_command("sudo apt install -y clamav clamav-daemon")

# Ensure automatic security updates are enabled
def enforce_auto_updates():
    stdout, _ = run_command("dpkg-query -W unattended-upgrades")
    if not stdout:
        logging.info("Installing unattended-upgrades...")
        run_command("sudo apt install -y unattended-upgrades")

    logging.info("Configuring unattended-upgrades...")
    run_command("sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure --priority=low unattended-upgrades")

# Ensure SSH is secured
def enforce_ssh_security():
    """Ensure SSH is secured"""
    try:
        sshd_config = "/etc/ssh/sshd_config"
        if not os.path.exists(sshd_config):
            logging.error(f"SSH config file not found at {sshd_config}")
            return False
            
        with open(sshd_config, "r") as file:
            lines = file.readlines()

        changes = False
        config_fixes = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no"
        }

        with open(sshd_config, "w") as file:
            for line in lines:
                for key, value in config_fixes.items():
                    if line.strip().startswith(key):
                        if f"{key} {value}" not in line:
                            logging.info(f"Fixing {key} in {sshd_config}")
                            line = f"{key} {value}\n"
                            changes = True
                file.write(line)

        if changes:
            stdout, returncode = run_command("sudo systemctl restart ssh")
            if returncode != 0:
                logging.error(f"Failed to restart SSH service: {stdout}")
                return False
                
        return True
    except Exception as e:
        logging.error(f"Error in enforce_ssh_security: {e}")
        return False

# Ensure fail2ban is installed for brute-force protection
def enforce_fail2ban():
    stdout, _ = run_command("command -v fail2ban-client")
    if not stdout:
        logging.info("Installing Fail2Ban...")
        run_command("sudo apt install -y fail2ban")
    run_command("sudo systemctl enable --now fail2ban")

# Ensure AppArmor is enabled
def enforce_apparmor():
    stdout, _ = run_command("aa-status")
    if "disabled" in stdout:
        logging.info("Enabling AppArmor...")
        run_command("sudo systemctl enable --now apparmor")

# Ensure SELinux is installed (for Debian-based systems)
def enforce_selinux():
    stdout, _ = run_command("command -v sestatus")
    if not stdout:
        logging.info("Installing SELinux utilities...")
        run_command("sudo apt install -y selinux-utils")
    
    stdout, _ = run_command("sestatus")
    if "disabled" in stdout:
        logging.info("Enabling SELinux...")
        run_command("sudo sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config")
        run_command("sudo reboot")

# Ensure password policies are enforced
def enforce_password_policy():
    """Ensure password policies are enforced"""
    try:
        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            logging.error(f"Login definitions file not found at {login_defs}")
            return False
            
        with open(login_defs, "r") as file:
            lines = file.readlines()

        changes = False
        config_fixes = {
            "PASS_MAX_DAYS": "90",
            "PASS_MIN_DAYS": "7",
            "PASS_WARN_AGE": "7"
        }

        with open(login_defs, "w") as file:
            for line in lines:
                for key, value in config_fixes.items():
                    if line.strip().startswith(key):
                        if f"{key} {value}" not in line:
                            logging.info(f"Updating {key} in {login_defs}")
                            line = f"{key} {value}\n"
                            changes = True
                file.write(line)
                
        return True
    except Exception as e:
        logging.error(f"Error in enforce_password_policy: {e}")
        return False

# Ensure automatic backups are configured
def enforce_backups():
    backup_script = "/usr/local/bin/auto_backup.sh"
    cron_job = "0 2 * * * /usr/local/bin/auto_backup.sh"

    if not os.path.exists(backup_script):
        logging.info("Creating backup script...")
        with open(backup_script, "w") as file:
            file.write("""#!/bin/bash
tar -czf /backup/system_backup_$(date +%F).tar.gz /etc /var /home
""")
        run_command("sudo chmod +x /usr/local/bin/auto_backup.sh")

    stdout, _ = run_command("crontab -l")
    if cron_job not in stdout:
        logging.info("Adding backup job to cron...")
        run_command(f'(crontab -l 2>/dev/null; echo "{cron_job}") | crontab -')

# Ensure disk encryption is enabled
def enforce_disk_encryption():
    stdout, _ = run_command("lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT")
    if "crypt" not in stdout:
        logging.info("WARNING: Disk encryption is NOT enabled. Configure LUKS manually.")

# Run all enforcement functions
def main():
    logging.info("Starting security enforcement...")
    print("\nRunning security enforcement script... Please wait.\n")
    
    success = True
    try:
        if not enforce_firewall():
            success = False
            logging.error("Firewall enforcement failed")
        if not enforce_antivirus():
            success = False
            logging.error("Antivirus enforcement failed")
        if not enforce_auto_updates():
            success = False
            logging.error("Auto updates enforcement failed")
        if not enforce_ssh_security():
            success = False
            logging.error("SSH security enforcement failed")
        if not enforce_fail2ban():
            success = False
            logging.error("Fail2ban enforcement failed")
        if not enforce_apparmor():
            success = False
            logging.error("AppArmor enforcement failed")
        if not enforce_selinux():
            success = False
            logging.error("SELinux enforcement failed")
        if not enforce_password_policy():
            success = False
            logging.error("Password policy enforcement failed")
        if not enforce_backups():
            success = False
            logging.error("Backup enforcement failed")
        if not enforce_disk_encryption():
            success = False
            logging.error("Disk encryption enforcement failed")

        if success:
            print("\nSecurity enforcement completed successfully!")
            logging.info("Security enforcement completed successfully.")
        else:
            print("\nSecurity enforcement completed with some failures. Check the log file for details.")
            logging.warning("Security enforcement completed with some failures.")
    
    except KeyboardInterrupt:
        print("\nExiting gracefully...")
        logging.warning("Security enforcement script was interrupted by the user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nFatal error during security enforcement: {str(e)}")
        logging.error(f"Fatal error during security enforcement: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

import subprocess


def block_ip(ip):
    """Block the given IP address using iptables."""
    try:
        # Construct the iptables command to drop packets from the IP
        command = f"sudo iptables -A INPUT -s {ip} -j DROP"
        # Execute the command
        subprocess.run(command, shell=True, check=True)
        print(f"Blocked IP {ip} using iptables.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip}: {e}")


# Example usage
if __name__ == "__main__":
    ip_to_block = "192.168.1.100"  # Replace with the IP you want to block
    block_ip(ip_to_block) 
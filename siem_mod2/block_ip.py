import subprocess


def block_ip(ip):
    """Block the given IP address using iptables."""
    try:
        # Construct the iptables command to drop packets from the IP, except ICMP
        # First drop all non-ICMP traffic
        command = f"sudo iptables -A INPUT -s {ip} -p tcp -j DROP && sudo iptables -A INPUT -s {ip} -p udp -j DROP"
        # Execute the command
        subprocess.run(command, shell=True, check=True)
        print(f"Blocked IP {ip} (except ICMP) using iptables.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip}: {e}")


# Example usage
if __name__ == "__main__":
    ip_to_block = "192.168.1.100"  # Replace with the IP you want to block
    block_ip(ip_to_block) 
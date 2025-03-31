import csv
import time
import os
from datetime import datetime
from scapy.all import sniff, TCP, UDP, IP, Raw
from collections import defaultdict
import threading
import subprocess

# Constants - Use absolute paths
SIEM_LOGS_DIR = "/var/log/siem_logs"
LOG_FILE = os.path.join(SIEM_LOGS_DIR, "network_logs.csv")
CSV_HEADER = [
    "s_no", "timestamp", "duration", "protocol_type", "src_ip", "src_port", "dst_ip", "dst_port",
    "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_type", "description"
]

# Global variables with thread-safe access
lock = threading.Lock()
packet_counts = defaultdict(int)  # Per source IP
service_counts = defaultdict(int)  # Per (dst_ip, proto, service)
host_counts = defaultdict(lambda: defaultdict(int))  # Per dst_ip
start_times = {}
s_no = 0
connection_history = defaultdict(list)  # Track connections for time-based features

def init_csv():
    """Initialize CSV file with headers."""
    with lock:
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)

def log_to_csv(file, entry):
    """Log entry to CSV file."""
    with lock:
        with open(file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(entry.values())

def console_alert(message, level="INFO"):
    """Print alert to console."""
    print(f"[{level}] {datetime.now()} - {message}")

def calculate_traffic_features(src_ip, dst_ip, proto, service, pkt):
    """Calculate time-based and host-based traffic features."""
    with lock:
        current_time = datetime.now()
        packet_counts[src_ip] += 1
        service_key = (dst_ip, proto, service)
        service_counts[service_key] += 1
        host_counts[dst_ip]["total"] += 1
        host_counts[dst_ip][service] += 1

        # Time window (e.g., last 2 seconds)
        time_window = 2
        connection_history[dst_ip].append((current_time, src_ip, pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0))
        connection_history[dst_ip] = [x for x in connection_history[dst_ip] if (current_time - x[0]).total_seconds() <= time_window]

        # Traffic features
        count = packet_counts[src_ip]
        srv_count = service_counts[service_key]
        serror_rate = 0.0  # Placeholder
        srv_serror_rate = 0.0
        rerror_rate = 0.0
        srv_rerror_rate = 0.0
        same_srv_rate = host_counts[dst_ip][service] / host_counts[dst_ip]["total"] if host_counts[dst_ip]["total"] > 0 else 0.0
        diff_srv_rate = 1.0 - same_srv_rate
        srv_diff_host_rate = len(set([x[1] for x in connection_history[dst_ip]])) / srv_count if srv_count > 0 else 0.0

        # Host-based features
        dst_host_count = host_counts[dst_ip]["total"]
        dst_host_srv_count = host_counts[dst_ip][service]
        dst_host_same_srv_rate = same_srv_rate
        dst_host_diff_srv_rate = diff_srv_rate
        dst_host_same_src_port_rate = len(set([x[2] for x in connection_history[dst_ip]])) / dst_host_count if dst_host_count > 0 else 0.0
        dst_host_srv_diff_host_rate = srv_diff_host_rate
        dst_host_serror_rate = 0.0
        dst_host_srv_serror_rate = 0.0
        dst_host_rerror_rate = 0.0
        dst_host_srv_rerror_rate = 0.0

        return {
            "count": count, "srv_count": srv_count, "serror_rate": serror_rate, "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate, "srv_rerror_rate": srv_rerror_rate, "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate, "srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_count": dst_host_count, "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate, "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate, "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
            "dst_host_serror_rate": dst_host_serror_rate, "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
            "dst_host_rerror_rate": dst_host_rerror_rate, "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate
        }

def detect_attack(pkt):
    """Detect potential attacks based on packet data and NSL-KDD features."""
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto = "Unknown"
    service = "Unknown"
    attack_type = "Normal"
    description = "Normal traffic"
    land = 0
    wrong_fragment = 0
    urgent = 0
    src_bytes = len(pkt)
    dst_bytes = 100  # Placeholder
    hot = 0
    num_failed_logins = 0
    logged_in = 0
    num_compromised = 0
    root_shell = 0
    su_attempted = 0
    num_root = 0
    num_file_creations = 0
    num_shells = 0
    num_access_files = 0
    num_outbound_cmds = 0
    is_host_login = 0
    is_guest_login = 0

    # Start time tracking
    with lock:
        if src_ip not in start_times:
            start_times[src_ip] = datetime.now()
        duration = (datetime.now() - start_times[src_ip]).total_seconds()

    if TCP in pkt:
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flag = pkt[TCP].flags
        service_map = {80: "HTTP", 22: "SSH", 23: "Telnet", 53: "DNS", 21: "FTP"}
        service = service_map.get(dst_port, service_map.get(src_port, "Unknown"))

        # Content features detection
        if Raw in pkt:
            payload = str(pkt[Raw].load).lower()
            if "login" in payload and "fail" in payload:
                num_failed_logins = 1
            elif "login" in payload:
                logged_in = 1
            if "guest" in payload:
                is_guest_login = 1
                attack_type, description = "R2L", "Guest login attempt"
            elif "root" in payload:
                root_shell = 1
                attack_type, description = "U2R", "Root shell attempt"
            elif "su" in payload:
                su_attempted = 1
                attack_type, description = "U2R", "Superuser attempt"

        # Attack detection
        traffic_features = calculate_traffic_features(src_ip, dst_ip, proto, service, pkt)
        if flag & 0x02 and traffic_features["count"] > 50:
            attack_type, description = "DoS", "Potential SYN flood"
        if src_ip == dst_ip and src_port == dst_port:
            land = 1
            attack_type, description = "DoS", "Land attack detected"
        if traffic_features["dst_host_diff_srv_rate"] > 0.5:
            attack_type, description = "Probe", "Port scanning detected"

    elif UDP in pkt:
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        service_map = {53: "DNS"}
        service = service_map.get(dst_port, service_map.get(src_port, "Unknown"))

        traffic_features = calculate_traffic_features(src_ip, dst_ip, proto, service, pkt)
        if traffic_features["count"] > 100:
            attack_type, description = "DoS", "Potential UDP flood detected"
        if traffic_features["dst_host_diff_srv_rate"] > 0.5:
            attack_type, description = "Probe", "Port scanning detected"

    if pkt[IP].frag > 0 or pkt[IP].flags & 0x01:
        wrong_fragment = 1
        attack_type, description = "Probe", "Fragmented packet detected"

    traffic_features = calculate_traffic_features(src_ip, dst_ip, proto, service, pkt)

    if attack_type != "Normal":
        block_ip(src_ip)  # Block the source IP if an attack is detected

    return {
        "s_no": None, "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"), "duration": round(duration, 2),
        "protocol_type": proto, "src_ip": src_ip, "src_port": src_port if TCP in pkt or UDP in pkt else 0,
        "dst_ip": dst_ip, "dst_port": dst_port if TCP in pkt or UDP in pkt else 0, "service": service,
        "flag": flag if TCP in pkt else "-", "src_bytes": src_bytes, "dst_bytes": dst_bytes,
        "land": land, "wrong_fragment": wrong_fragment, "urgent": urgent, "hot": hot,
        "num_failed_logins": num_failed_logins, "logged_in": logged_in, "num_compromised": num_compromised,
        "root_shell": root_shell, "su_attempted": su_attempted, "num_root": num_root,
        "num_file_creations": num_file_creations, "num_shells": num_shells, "num_access_files": num_access_files,
        "num_outbound_cmds": num_outbound_cmds, "is_host_login": is_host_login, "is_guest_login": is_guest_login,
        **traffic_features, "attack_type": attack_type, "description": description
    }

def process_packet(pkt):
    """Process each packet and log it."""
    global s_no
    if IP not in pkt:
        return

    with lock:
        s_no += 1

    detection = detect_attack(pkt)
    detection["s_no"] = s_no
    log_to_csv(LOG_FILE, detection)

def block_ip(ip):
    """Block the given IP address using UFW."""
    try:
        command = f"sudo ufw deny from {ip}"
        subprocess.run(command, shell=True, check=True)
        console_alert(f"Blocked IP {ip} due to detected attack", "WARNING")
    except Exception as e:
        console_alert(f"Failed to block IP {ip}: {str(e)}", "ERROR")

if __name__ == "__main__":
    init_csv()
    print("Starting SIEM packet capture...")
    # Dynamically detect interfaces or specify the correct one
    import netifaces
    interfaces = netifaces.interfaces()
    print(f"Available interfaces: {interfaces}")
    sniff(iface=interfaces, prn=process_packet, store=0)  # Use all available interfaces

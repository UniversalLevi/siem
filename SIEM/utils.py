import threading
import queue
import json
import os
import hashlib
import csv
from datetime import datetime
import socket
import sqlite3
from scapy.all import IP, TCP, UDP

# Threading Utilities
data_queue = queue.Queue()
lock = threading.Lock()

def thread_worker(func, *args):
    """Generic thread worker function."""
    func(*args)

def start_thread(target, args=()):
    """Start a thread with the given target function and arguments."""
    thread = threading.Thread(target=target, args=args)
    thread.daemon = True
    thread.start()
    return thread

# Data Preprocessing Functions
def clean_packet_data(pkt):
    """Remove noise or invalid entries from packet data."""
    if IP not in pkt:
        return None
    return pkt

def packet_to_dict(pkt):
    """Convert raw packet data to structured dictionary."""
    return {
        "src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst,
        "proto": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Unknown",
        "src_bytes": len(pkt)
    }

# Feature Extraction & Normalization
def extract_features(pkt):
    """Extract features like packet size, protocol."""
    return {
        "size": len(pkt),
        "proto": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Unknown"
    }

def normalize_value(value, min_val, max_val):
    """Normalize numeric values."""
    return (value - min_val) / (max_val - min_val) if max_val > min_val else 0

# Logging & Alerting System
def log_to_csv(filename, data):
    """Log events to CSV with timestamps."""
    with lock:
        with open(filename, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(data)

def console_alert(message, severity="INFO"):
    """Print console alerts with severity levels."""
    try:
        print(f"[{severity}] {datetime.now()} - {message}")
    except KeyboardInterrupt:
        pass  # Ignore interrupt during printing

# Network Packet Analysis
def parse_packet(pkt):
    """Parse Scapy packet objects."""
    return {
        "src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst,
        "src_port": pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0,
        "dst_port": pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0
    }

# IP & Traffic Filtering
def is_ip_in_range(ip, subnet):
    """Filter traffic by IP range or subnet."""
    return ip.startswith(subnet)

# Anomaly Detection Helpers
def detect_spike(count, threshold=100):
    """Detect sudden spikes in packet rates."""
    return count > threshold

# Database Connection Helpers
def connect_db(db_name="siem.db"):
    """Connect to SQLite database."""
    return sqlite3.connect(db_name)

def insert_log(conn, data):
    """Insert log data into database."""
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (timestamp, src_ip, dst_ip) VALUES (?, ?, ?)", 
                   (data[1], data[2], data[3]))
    conn.commit()

# Configuration Management
def load_config(file="config.json"):
    """Load settings from JSON file."""
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"log_file": "network_logs.csv"}

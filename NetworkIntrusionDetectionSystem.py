from scapy.all import sniff, IP, TCP, ICMP
import datetime

LOG_FILE = "alerts.log"

def log_alert(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[ALERT] {message}")

def analyze_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        if ICMP in packet:
            log_alert(f"ICMP Ping detected: {src} -> {dst}")
        elif TCP in packet:
            if packet[TCP].flags == "S":
                log_alert(f"TCP SYN Scan detected: {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}")
            if packet.haslayer("Raw"):
                payload = packet["Raw"].load.decode(errors="ignore")
                if "GET /etc/passwd" in payload:
                    log_alert(f"Suspicious HTTP GET detected from {src} to {dst}: {payload}")

def start_ids():
    print("=== Python IDS Started ===")
    print("Monitoring network packets... Press Ctrl+C to stop.")
    sniff(prn=analyze_packet, store=False)

if _name_ == "_main_":
    start_ids()
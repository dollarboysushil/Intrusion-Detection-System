import subprocess
import time
import os
import csv
import requests
from datetime import datetime

# Configuration
INTERFACE = "Ethernet"  # Change this to your real network interface
DURATION = 10  # Capture duration in seconds
ENDPOINT = "http://127.0.0.1:8000/predict/"
CFM_BAT = "cfm.bat"
OUTPUT_DIR = "captures"
CSV_DIR = "csv_output"

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)

def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def capture_pcap(pcap_file):
    print(f"[*] Capturing traffic to {pcap_file} for {DURATION} seconds...")
    subprocess.run([
        "tshark", "-i", INTERFACE,
        "-a", f"duration:{DURATION}",
        "-w", pcap_file
    ], check=True)

def is_pcapng(file_path):
    """Check magic bytes to see if it's a pcapng file"""
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        return magic == b'\x0A\x0D\x0D\x0A'

def convert_pcap_to_csv(pcap_file, output_dir):
    print(f"[*] Preparing to convert {pcap_file} to CSV using {CFM_BAT}")

    # Step 1: If pcap is actually pcapng, convert it
    if is_pcapng(pcap_file):
        print("[!] Detected pcapng format. Converting to libpcap...")
        converted_file = pcap_file.replace(".pcap", "_converted.pcap")
        try:
            subprocess.run(['editcap', '-F', 'libpcap', pcap_file, converted_file], check=True)
            print(f"[✓] Converted to {converted_file}")
            pcap_file = converted_file  # update to use the converted file
        except subprocess.CalledProcessError as e:
            print(f"[X] editcap failed: {e}")
            return

    # Step 2: Call CICFlowMeter (cfm.bat)
    try:
        subprocess.run([CFM_BAT, pcap_file, output_dir], shell=True, check=True)
        print(f"[✓] CSV generated from {pcap_file}")
    except subprocess.CalledProcessError as e:
        print(f"[X] Failed to run CICFlowMeter: {e}")

def find_csv_file(pcap_file_name):
    base_name = os.path.splitext(os.path.basename(pcap_file_name))[0]
    for file in os.listdir(CSV_DIR):
        if file.startswith(base_name) and file.endswith("_Flow.csv"):
            return os.path.join(CSV_DIR, file)
    return None

def send_csv_rows(csv_file):
    print(f"[*] Sending rows from {csv_file} to {ENDPOINT}")
    with open(csv_file, newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            try:
                response = requests.post(ENDPOINT, json=row)
                print(f"[>] Sent row, status: {response.status_code}")
            except Exception as e:
                print(f"[!] Failed to send row: {e}")

def main():
    while True:
        timestamp = get_timestamp()
        pcap_path = os.path.join(OUTPUT_DIR, f"{timestamp}.pcap")

        # Step 1: Capture traffic
        capture_pcap(pcap_path)

        # Step 2: Convert pcap to CSV
        convert_pcap_to_csv(pcap_path, CSV_DIR)

        # Step 3: Find generated CSV
        csv_file = find_csv_file(pcap_path)
        if csv_file:
            print(f"[+] Found CSV file: {csv_file}")
            send_csv_rows(csv_file)
        else:
            print("[!] CSV file not found. Skipping this round.")

        print(">>> Looping...\n")

if __name__ == "__main__":
    main()

import subprocess
import time
import os
import csv
import requests
from datetime import datetime

# Configuration
INTERFACE = "Ethernet"  # Change this to your real network interface
DURATION = 30  # Capture duration in seconds
ENDPOINT = "http://192.168.1.64:8080/predict"
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

def convert_pcap_to_csv(pcap_file, output_dir):
    print(f"[*] Converting {pcap_file} to CSV using {CFM_BAT}")
    subprocess.run([CFM_BAT, pcap_file, output_dir], shell=True, check=True)

def find_csv_file(pcap_file_name):
    base_name = os.path.basename(pcap_file_name)
    expected_csv = f"{base_name}_Flow.csv"
    full_path = os.path.join(CSV_DIR, expected_csv)
    if os.path.exists(full_path):
        return full_path
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

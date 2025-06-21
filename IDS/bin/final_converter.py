import subprocess
import time
import os
import csv
import requests
import threading
import queue
import shutil
import tempfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from pathlib import Path
import json
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Configuration
INTERFACE = "Ethernet"  # Change this to your real network interface
DURATION = 10  # Capture duration in seconds (back to your original 10s)
ENDPOINT = "http://localhost:8000/predict/"
ENDPOINT_HOST = "localhost"
ENDPOINT_PORT = "8080"
CFM_BAT = "cfm.bat"
OUTPUT_DIR = "captures"
CSV_DIR = "csv_output"
TEMP_DIR = "temp_processing"
MAX_WORKERS = 2  # Reduced to prevent connection pool exhaustion
CYCLE_COOLDOWN = 2  # Seconds to wait between cycles for cleanup
MAX_FLOWS_PER_CYCLE = 50  # Reduced to prevent bottleneck
PREDICTION_TIMEOUT = 30  # Maximum time to spend on predictions per cycle
REQUEST_TIMEOUT = 10  # Individual request timeout (increased for stability)

# Connection pool configuration
POOL_CONNECTIONS = 10
POOL_MAXSIZE = 10
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.3

# Setup logging with ASCII-safe format and UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('intrusion_detection.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Suppress urllib3 warnings about connection pool
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

# Ensure directories exist
for directory in [OUTPUT_DIR, CSV_DIR, TEMP_DIR]:
    os.makedirs(directory, exist_ok=True)

# Global state management
processing_lock = threading.Lock()
current_cycle = 0
shutdown_event = threading.Event()

# Global session with connection pooling
session = None
session_lock = threading.Lock()


def create_session():
    """Create a session with proper connection pooling and retry strategy"""
    global session

    with session_lock:
        if session is None:
            session = requests.Session()

            # Configure retry strategy
            retry_strategy = Retry(
                total=MAX_RETRIES,
                backoff_factor=BACKOFF_FACTOR,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["POST"]
            )

            # Configure HTTP adapter with connection pooling
            adapter = HTTPAdapter(
                pool_connections=POOL_CONNECTIONS,
                pool_maxsize=POOL_MAXSIZE,
                max_retries=retry_strategy
            )

            session.mount("http://", adapter)
            session.mount("https://", adapter)

            logger.info(f"Created session with pool size: {POOL_MAXSIZE}")

    return session


def cleanup_session():
    """Clean up the global session"""
    global session

    with session_lock:
        if session is not None:
            session.close()
            session = None
            logger.info("Closed HTTP session")


class CycleManager:
    """Manages complete isolation between processing cycles"""

    def __init__(self):
        self.cycle_number = 0
        self.active_processes = set()
        self.lock = threading.Lock()

    def start_cycle(self):
        with self.lock:
            self.cycle_number += 1
            cycle_id = f"cycle_{self.cycle_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            logger.info(f"=== Starting {cycle_id} ===")
            return cycle_id

    def end_cycle(self, cycle_id):
        with self.lock:
            logger.info(f"=== Ending {cycle_id} ===")
            # Force cleanup of any remaining processes
            self.cleanup_processes()

    def cleanup_processes(self):
        """Kill any hanging processes that might affect next cycle"""
        try:
            # Kill any remaining tshark processes
            subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"],
                           capture_output=True, shell=True)
            # Small delay to ensure cleanup
            time.sleep(1)
        except Exception as e:
            logger.warning(f"Process cleanup warning: {e}")


cycle_manager = CycleManager()


def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def create_isolated_workspace(cycle_id):
    """Create isolated workspace for each cycle"""
    workspace = os.path.join(TEMP_DIR, cycle_id)
    os.makedirs(workspace, exist_ok=True)
    return workspace


def cleanup_workspace(workspace):
    """Clean up workspace completely"""
    try:
        if os.path.exists(workspace):
            shutil.rmtree(workspace)
            logger.info(f"Cleaned up workspace: {workspace}")
    except Exception as e:
        logger.error(f"Failed to cleanup workspace {workspace}: {e}")


def capture_and_process_cycle():
    """Complete isolated cycle: capture -> convert -> predict -> cleanup"""
    cycle_id = cycle_manager.start_cycle()
    workspace = create_isolated_workspace(cycle_id)

    try:
        # Step 1: Capture with complete isolation
        pcap_file = capture_traffic_isolated(cycle_id, workspace)
        if not pcap_file:
            return False

        # Step 2: Convert with fresh CICFlowMeter instance
        csv_file = convert_pcap_isolated(pcap_file, workspace, cycle_id)
        if not csv_file:
            return False

        # Step 3: Process predictions
        success = process_predictions_isolated(csv_file, cycle_id)

        return success

    except Exception as e:
        logger.error(f"Error in cycle {cycle_id}: {e}")
        return False
    finally:
        # Step 4: Complete cleanup
        cycle_manager.end_cycle(cycle_id)
        cleanup_workspace(workspace)

        # Cooldown period to ensure complete state reset
        if CYCLE_COOLDOWN > 0:
            logger.info(f"Cycle cooldown: {CYCLE_COOLDOWN}s")
            time.sleep(CYCLE_COOLDOWN)


def capture_traffic_isolated(cycle_id, workspace):
    """Capture traffic with complete isolation from endpoint"""
    timestamp = get_timestamp()
    pcap_file = os.path.join(workspace, f"{cycle_id}_{timestamp}.pcap")

    logger.info(f"[{cycle_id}] Starting capture for {DURATION} seconds...")

    # Enhanced filter to exclude endpoint traffic and ensure clean capture
    filter_expr = f"not (host {ENDPOINT_HOST} and port {ENDPOINT_PORT})"

    try:
        # Use absolute timeout and ensure process cleanup
        result = subprocess.run([
            "tshark", "-i", INTERFACE,
            "-a", f"duration:{DURATION}",
            "-f", filter_expr,
            "-F", "pcap",
            "-w", pcap_file,
            "-q"  # Quiet mode for cleaner logs
        ], check=True, timeout=DURATION + 10, capture_output=True, text=True)

        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
            logger.info(
                f"[{cycle_id}] Capture successful: {pcap_file} ({os.path.getsize(pcap_file)} bytes)")
            return pcap_file
        else:
            logger.warning(
                f"[{cycle_id}] Capture resulted in empty or missing file")
            return None

    except subprocess.TimeoutExpired:
        logger.error(f"[{cycle_id}] Capture timeout - killing tshark process")
        subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"],
                       capture_output=True, shell=True)
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"[{cycle_id}] Capture failed: {e}")
        if e.stderr:
            logger.error(f"[{cycle_id}] tshark stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"[{cycle_id}] Unexpected capture error: {e}")
        return None


def convert_pcap_isolated(pcap_file, workspace, cycle_id):
    """Convert PCAP to CSV with isolated CICFlowMeter instance"""
    logger.info(f"[{cycle_id}] Converting PCAP to CSV...")

    # Create isolated output directory for this cycle
    csv_output_dir = os.path.join(workspace, "csv_output")
    os.makedirs(csv_output_dir, exist_ok=True)

    try:
        # Run CICFlowMeter with timeout and isolated workspace
        result = subprocess.run([
            CFM_BAT, pcap_file, csv_output_dir
        ], shell=True, check=True, timeout=60, capture_output=True, text=True)

        # Find generated CSV file
        csv_file = find_csv_file_in_dir(pcap_file, csv_output_dir)

        if csv_file and os.path.exists(csv_file):
            row_count = count_csv_rows(csv_file)
            logger.info(
                f"[{cycle_id}] CSV conversion successful: {csv_file} ({row_count} flows)")
            return csv_file
        else:
            logger.warning(
                f"[{cycle_id}] No CSV file generated from {pcap_file}")
            return None

    except subprocess.TimeoutExpired:
        logger.error(f"[{cycle_id}] CSV conversion timeout")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"[{cycle_id}] CSV conversion failed: {e}")
        if e.stdout:
            logger.error(f"[{cycle_id}] CFM stdout: {e.stdout}")
        if e.stderr:
            logger.error(f"[{cycle_id}] CFM stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"[{cycle_id}] Unexpected conversion error: {e}")
        return None


def find_csv_file_in_dir(pcap_file, csv_dir):
    """Find CSV file in specific directory"""
    try:
        csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]
        if csv_files:
            # Return the most recent CSV file
            csv_files.sort(key=lambda x: os.path.getmtime(
                os.path.join(csv_dir, x)), reverse=True)
            return os.path.join(csv_dir, csv_files[0])
    except Exception:
        pass
    return None


def count_csv_rows(csv_file):
    """Count rows in CSV file"""
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            return sum(1 for line in f) - 1  # Subtract header
    except Exception:
        return 0


def process_predictions_isolated(csv_file, cycle_id):
    """Process predictions with connection pooling and batching"""
    logger.info(f"[{cycle_id}] Processing predictions...")

    try:
        # Ensure session is created
        http_session = create_session()

        # Read CSV with error handling
        rows = []
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as file:
            reader = csv.DictReader(file)
            rows = list(reader)

        if not rows:
            logger.warning(f"[{cycle_id}] No data rows found in CSV")
            return True  # Not an error condition

        total_flows = len(rows)

        # Limit flows to prevent bottleneck
        if total_flows > MAX_FLOWS_PER_CYCLE:
            logger.info(
                f"[{cycle_id}] Limiting flows from {total_flows} to {MAX_FLOWS_PER_CYCLE}")
            # Sample flows strategically (first, middle, last portions)
            step = total_flows // MAX_FLOWS_PER_CYCLE
            rows = rows[::step][:MAX_FLOWS_PER_CYCLE]

        logger.info(
            f"[{cycle_id}] Sending {len(rows)} flows for prediction (from {total_flows} total)")

        # Track predictions for this cycle
        predictions = {
            'normal': 0,
            'attack': 0,
            'errors': 0,
            'total': len(rows),
            'original_total': total_flows
        }

        # Process in smaller batches to avoid connection pool exhaustion
        batch_size = MAX_WORKERS
        completed_requests = 0

        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]

            # Process batch with controlled parallelism
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Submit batch requests
                future_to_row = {
                    executor.submit(send_prediction_request, row, cycle_id, http_session): j
                    for j, row in enumerate(batch)
                }

                # Collect batch results
                for future in as_completed(future_to_row, timeout=REQUEST_TIMEOUT * 2):
                    row_index = future_to_row[future]
                    try:
                        result = future.result(timeout=REQUEST_TIMEOUT)
                        completed_requests += 1

                        if result.get('success'):
                            prediction = result.get(
                                'prediction', 'unknown').lower()
                            if 'attack' in prediction or 'malicious' in prediction:
                                predictions['attack'] += 1
                            else:
                                predictions['normal'] += 1
                        else:
                            predictions['errors'] += 1

                    except Exception as e:
                        predictions['errors'] += 1
                        logger.debug(
                            f"[{cycle_id}] Error processing batch row {row_index}: {e}")

            # Small delay between batches to prevent overwhelming the endpoint
            if i + batch_size < len(rows):
                time.sleep(0.5)

            # Log progress
            progress = min(i + batch_size, len(rows))
            logger.info(
                f"[{cycle_id}] Progress: {progress}/{len(rows)} flows processed")

        # Log cycle summary
        log_cycle_summary(cycle_id, predictions)

        # Success if we completed at least 70% of requests
        success_rate = completed_requests / len(rows) if len(rows) > 0 else 0
        logger.info(f"[{cycle_id}] Success rate: {success_rate:.2%}")
        return success_rate >= 0.7

    except Exception as e:
        logger.error(f"[{cycle_id}] Error processing predictions: {e}")
        return False


def send_prediction_request(row, cycle_id, http_session):
    """Send individual prediction request with session reuse"""
    try:
        # Clean the row data - only include numeric/essential fields
        cleaned_row = {}
        for k, v in row.items():
            if v is not None and v != '' and v != 'NaN':
                # Try to convert to float if possible (for numeric fields)
                try:
                    cleaned_row[k] = float(v)
                except (ValueError, TypeError):
                    cleaned_row[k] = str(v)

        headers = {
            'Content-Type': 'application/json',
            'X-Cycle-ID': cycle_id,
            'Connection': 'keep-alive'  # Ensure connection reuse
        }

        response = http_session.post(
            ENDPOINT,
            json=cleaned_row,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            try:
                result = response.json()
                return {
                    'success': True,
                    'prediction': result.get('prediction', 'unknown'),
                    'status_code': response.status_code
                }
            except json.JSONDecodeError:
                return {
                    'success': True,
                    'prediction': 'normal',  # Default assumption
                    'status_code': response.status_code
                }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}",
                'status_code': response.status_code
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Request timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Connection error'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Request error: {str(e)[:50]}'}
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)[:50]}'}


def log_cycle_summary(cycle_id, predictions):
    """Log comprehensive cycle summary"""
    total = predictions['total']
    original_total = predictions.get('original_total', total)
    normal = predictions['normal']
    attack = predictions['attack']
    errors = predictions['errors']

    attack_percentage = (attack / total * 100) if total > 0 else 0

    logger.info(f"[{cycle_id}] CYCLE SUMMARY:")
    if original_total != total:
        logger.info(
            f"[{cycle_id}]   Original flows: {original_total} (sampled: {total})")
    else:
        logger.info(f"[{cycle_id}]   Total flows: {total}")
    logger.info(f"[{cycle_id}]   Normal: {normal} ({normal/total*100:.1f}%)")
    logger.info(f"[{cycle_id}]   Attack: {attack} ({attack_percentage:.1f}%)")
    logger.info(f"[{cycle_id}]   Errors: {errors} ({errors/total*100:.1f}%)")

    # Alert on high attack percentage
    if attack_percentage > 10:  # Threshold for alert
        logger.warning(
            f"[{cycle_id}] [!] HIGH ATTACK TRAFFIC DETECTED: {attack_percentage:.1f}%")
    else:
        logger.info(f"[{cycle_id}] [OK] Normal traffic levels")


def monitor_system_health():
    """Monitor system health and cleanup"""
    while not shutdown_event.is_set():
        try:
            # Check disk space
            check_disk_space()

            # Cleanup old files
            cleanup_old_files()

            # Check for zombie processes
            cleanup_zombie_processes()

            # Wait before next check
            shutdown_event.wait(300)  # Check every 5 minutes

        except Exception as e:
            logger.error(f"Health monitor error: {e}")
            shutdown_event.wait(60)  # Wait 1 minute on error


def check_disk_space():
    """Check available disk space"""
    try:
        total, used, free = shutil.disk_usage(".")
        free_gb = free // (1024**3)

        if free_gb < 1:  # Less than 1GB free
            logger.warning(f"Low disk space: {free_gb}GB free")
            # Emergency cleanup
            emergency_cleanup()

    except Exception as e:
        logger.error(f"Disk space check error: {e}")


def cleanup_old_files():
    """Cleanup old files from all directories"""
    directories_to_clean = [OUTPUT_DIR, CSV_DIR, TEMP_DIR]

    for directory in directories_to_clean:
        if not os.path.exists(directory):
            continue

        try:
            # Get all files with timestamps
            files = []
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath):
                        files.append((filepath, os.path.getmtime(filepath)))

            # Sort by modification time (newest first)
            files.sort(key=lambda x: x[1], reverse=True)

            # Keep only the 10 most recent files
            if len(files) > 10:
                for filepath, _ in files[10:]:
                    try:
                        os.remove(filepath)
                        logger.debug(f"Cleaned up old file: {filepath}")
                    except Exception as e:
                        logger.error(f"Failed to remove {filepath}: {e}")

            # Remove empty directories
            for root, dirs, filenames in os.walk(directory, topdown=False):
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    try:
                        if not os.listdir(dirpath):  # Empty directory
                            os.rmdir(dirpath)
                    except Exception:
                        pass  # Ignore errors

        except Exception as e:
            logger.error(f"Error cleaning {directory}: {e}")


def emergency_cleanup():
    """Emergency cleanup when disk space is low"""
    logger.warning("Performing emergency cleanup...")

    for directory in [OUTPUT_DIR, CSV_DIR, TEMP_DIR]:
        try:
            if os.path.exists(directory):
                shutil.rmtree(directory)
                os.makedirs(directory, exist_ok=True)
                logger.info(f"Emergency cleanup completed for {directory}")
        except Exception as e:
            logger.error(f"Emergency cleanup failed for {directory}: {e}")


def cleanup_zombie_processes():
    """Kill any zombie tshark or java processes"""
    try:
        # Kill hanging tshark processes
        subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"],
                       capture_output=True, shell=True)

        # Kill hanging java processes (CICFlowMeter)
        result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq java.exe"],
                                capture_output=True, text=True, shell=True)

        if "java.exe" in result.stdout:
            subprocess.run(["taskkill", "/F", "/IM", "java.exe"],
                           capture_output=True, shell=True)
            logger.info("Cleaned up zombie java processes")

    except Exception as e:
        logger.error(f"Process cleanup error: {e}")


def main():
    """Main function with complete cycle management"""
    logger.info("=== Starting Robust Network Intrusion Detection System ===")
    logger.info(f"Interface: {INTERFACE}")
    logger.info(f"Capture duration: {DURATION} seconds")
    logger.info(f"Endpoint: {ENDPOINT}")
    logger.info(f"Filtering traffic to {ENDPOINT_HOST}:{ENDPOINT_PORT}")
    logger.info(f"Cycle cooldown: {CYCLE_COOLDOWN} seconds")
    logger.info(f"Max workers: {MAX_WORKERS}")
    logger.info(f"Connection pool size: {POOL_MAXSIZE}")

    # Create initial session
    create_session()

    # Start health monitor thread
    health_thread = threading.Thread(target=monitor_system_health, daemon=True)
    health_thread.start()

    consecutive_failures = 0
    max_consecutive_failures = 5

    try:
        while not shutdown_event.is_set():
            try:
                # Run complete isolated cycle
                success = capture_and_process_cycle()

                if success:
                    consecutive_failures = 0
                    logger.info("[OK] Cycle completed successfully")
                else:
                    consecutive_failures += 1
                    logger.warning(
                        f"[FAIL] Cycle failed ({consecutive_failures}/{max_consecutive_failures})")

                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(
                            "Too many consecutive failures - performing system reset")
                        # Emergency reset
                        cycle_manager.cleanup_processes()
                        cleanup_session()
                        create_session()  # Recreate session
                        emergency_cleanup()
                        consecutive_failures = 0
                        time.sleep(30)  # Extended cooldown after reset

                # Brief pause between cycles (in addition to cooldown)
                time.sleep(1)

            except KeyboardInterrupt:
                logger.info("Shutdown requested by user")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                consecutive_failures += 1
                time.sleep(10)  # Wait before retry

    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        logger.info("Shutting down...")
        shutdown_event.set()

        # Final cleanup
        cleanup_session()
        cycle_manager.cleanup_processes()
        cleanup_old_files()

        logger.info("=== Network Intrusion Detection System Stopped ===")


if __name__ == "__main__":
    main()

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
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing
import logging
from pathlib import Path
import json
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import signal
import sys
from dataclasses import dataclass
from typing import Optional, Dict, Any
import pickle

# Configuration
INTERFACE = "Ethernet"
DURATION = 10
ENDPOINT = "http://localhost:8000/predict/"
ENDPOINT_HOST = "localhost"
ENDPOINT_PORT = "8080"
CFM_BAT = "cfm.bat"
OUTPUT_DIR = "captures"
CSV_DIR = "csv_output"
TEMP_DIR = "temp_processing"
MAX_WORKERS = 4  # Increased for better parallelism
CYCLE_COOLDOWN = 1  # Reduced since we have overlap now
MAX_FLOWS_PER_CYCLE = 100  # Increased since processing is faster
PREDICTION_TIMEOUT = 60
REQUEST_TIMEOUT = 15

# Multiprocessing configuration
NUM_CAPTURE_PROCESSES = 1  # Keep capture single-threaded for stability
NUM_CONVERSION_PROCESSES = 2  # Multiple conversion processes
NUM_PREDICTION_PROCESSES = 2  # Multiple prediction processes
QUEUE_MAX_SIZE = 10  # Maximum items in inter-process queues

# Connection pool configuration
POOL_CONNECTIONS = 15
POOL_MAXSIZE = 15
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.3


@dataclass
class TaskItem:
    """Data structure for passing tasks between processes"""
    task_id: str
    task_type: str
    file_path: Optional[str] = None
    workspace: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None

# Setup multiprocessing-safe logging


def setup_logging():
    """Setup logging that works across processes"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - PID:%(process)d - %(threadName)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('intrusion_detection.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

    # Suppress urllib3 warnings
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    return logging.getLogger(__name__)


# Global logger (will be set in each process)
logger = None

# Ensure directories exist
for directory in [OUTPUT_DIR, CSV_DIR, TEMP_DIR]:
    os.makedirs(directory, exist_ok=True)


class MultiprocessingIDS:
    """Main multiprocessing intrusion detection system"""

    def __init__(self):
        self.capture_queue = multiprocessing.Queue(maxsize=QUEUE_MAX_SIZE)
        self.conversion_queue = multiprocessing.Queue(maxsize=QUEUE_MAX_SIZE)
        self.prediction_queue = multiprocessing.Queue(maxsize=QUEUE_MAX_SIZE)
        self.result_queue = multiprocessing.Queue()

        self.shutdown_event = multiprocessing.Event()
        self.stats_lock = multiprocessing.Lock()
        self.stats = multiprocessing.Manager().dict({
            'cycles_completed': 0,
            'total_flows_processed': 0,
            'attacks_detected': 0,
            'errors': 0,
            'start_time': time.time()
        })

        self.processes = []

    def start(self):
        """Start all worker processes"""
        global logger
        logger = setup_logging()

        logger.info(
            "=== Starting Multiprocessing Network Intrusion Detection System ===")
        logger.info(f"Configuration:")
        logger.info(f"  - Capture processes: {NUM_CAPTURE_PROCESSES}")
        logger.info(f"  - Conversion processes: {NUM_CONVERSION_PROCESSES}")
        logger.info(f"  - Prediction processes: {NUM_PREDICTION_PROCESSES}")
        logger.info(f"  - Interface: {INTERFACE}")
        logger.info(f"  - Capture duration: {DURATION}s")
        logger.info(f"  - Endpoint: {ENDPOINT}")

        # Start capture processes
        for i in range(NUM_CAPTURE_PROCESSES):
            p = multiprocessing.Process(
                target=capture_worker,
                args=(self.capture_queue, self.shutdown_event, i)
            )
            p.start()
            self.processes.append(p)
            logger.info(f"Started capture worker {i} (PID: {p.pid})")

        # Start conversion processes
        for i in range(NUM_CONVERSION_PROCESSES):
            p = multiprocessing.Process(
                target=conversion_worker,
                args=(self.capture_queue, self.conversion_queue,
                      self.shutdown_event, i)
            )
            p.start()
            self.processes.append(p)
            logger.info(f"Started conversion worker {i} (PID: {p.pid})")

        # Start prediction processes
        for i in range(NUM_PREDICTION_PROCESSES):
            p = multiprocessing.Process(
                target=prediction_worker,
                args=(self.conversion_queue, self.result_queue,
                      self.shutdown_event, i)
            )
            p.start()
            self.processes.append(p)
            logger.info(f"Started prediction worker {i} (PID: {p.pid})")

        # Start result collector
        collector_process = multiprocessing.Process(
            target=result_collector,
            args=(self.result_queue, self.stats,
                  self.stats_lock, self.shutdown_event)
        )
        collector_process.start()
        self.processes.append(collector_process)
        logger.info(f"Started result collector (PID: {collector_process.pid})")

        # Start stats reporter
        stats_process = multiprocessing.Process(
            target=stats_reporter,
            args=(self.stats, self.stats_lock, self.shutdown_event)
        )
        stats_process.start()
        self.processes.append(stats_process)
        logger.info(f"Started stats reporter (PID: {stats_process.pid})")

    def stop(self):
        """Stop all processes gracefully"""
        logger.info("Initiating graceful shutdown...")
        self.shutdown_event.set()

        # Wait for processes to finish
        for p in self.processes:
            p.join(timeout=30)
            if p.is_alive():
                logger.warning(f"Force terminating process {p.pid}")
                p.terminate()
                p.join()

        # Close queues
        self.capture_queue.close()
        self.conversion_queue.close()
        self.prediction_queue.close()
        self.result_queue.close()

        logger.info("All processes stopped")


def capture_worker(output_queue: multiprocessing.Queue, shutdown_event: multiprocessing.Event, worker_id: int):
    """Continuously capture network traffic"""
    logger = setup_logging()
    logger.info(f"Capture worker {worker_id} started")

    cycle_count = 0

    try:
        while not shutdown_event.is_set():
            try:
                cycle_count += 1
                task_id = f"capture_{worker_id}_{cycle_count}_{int(time.time())}"

                # Create workspace for this capture
                workspace = create_isolated_workspace(task_id)

                # Capture traffic
                pcap_file = capture_traffic_isolated(
                    task_id, workspace, logger)

                if pcap_file and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                    # Create task item for conversion queue
                    task_item = TaskItem(
                        task_id=task_id,
                        task_type="conversion",
                        file_path=pcap_file,
                        workspace=workspace,
                        timestamp=datetime.now()
                    )

                    # Send to conversion queue (non-blocking with timeout)
                    try:
                        output_queue.put(task_item, timeout=5)
                        logger.info(f"[{task_id}] Queued for conversion")
                    except queue.Full:
                        logger.warning(
                            f"[{task_id}] Conversion queue full, skipping")
                        cleanup_workspace(workspace)
                else:
                    logger.warning(f"[{task_id}] Capture failed or empty")
                    cleanup_workspace(workspace)

                # Small delay to prevent overwhelming
                time.sleep(1)

            except Exception as e:
                logger.error(f"Capture worker {worker_id} error: {e}")
                time.sleep(5)

    except KeyboardInterrupt:
        pass
    finally:
        logger.info(f"Capture worker {worker_id} shutting down")


def conversion_worker(input_queue: multiprocessing.Queue, output_queue: multiprocessing.Queue,
                      shutdown_event: multiprocessing.Event, worker_id: int):
    """Convert PCAP files to CSV"""
    logger = setup_logging()
    logger.info(f"Conversion worker {worker_id} started")

    try:
        while not shutdown_event.is_set():
            try:
                # Get task from input queue
                try:
                    task_item = input_queue.get(timeout=5)
                except queue.Empty:
                    continue

                task_id = task_item.task_id
                pcap_file = task_item.file_path
                workspace = task_item.workspace

                logger.info(f"[{task_id}] Converting PCAP to CSV")

                # Convert PCAP to CSV
                csv_file = convert_pcap_isolated(
                    pcap_file, workspace, task_id, logger)

                if csv_file and os.path.exists(csv_file):
                    # Create task for prediction queue
                    prediction_task = TaskItem(
                        task_id=task_id,
                        task_type="prediction",
                        file_path=csv_file,
                        workspace=workspace,
                        timestamp=datetime.now()
                    )

                    try:
                        output_queue.put(prediction_task, timeout=5)
                        logger.info(f"[{task_id}] Queued for prediction")
                    except queue.Full:
                        logger.warning(
                            f"[{task_id}] Prediction queue full, skipping")
                        cleanup_workspace(workspace)
                else:
                    logger.warning(f"[{task_id}] Conversion failed")
                    cleanup_workspace(workspace)

            except Exception as e:
                logger.error(f"Conversion worker {worker_id} error: {e}")
                time.sleep(2)

    except KeyboardInterrupt:
        pass
    finally:
        logger.info(f"Conversion worker {worker_id} shutting down")


def prediction_worker(input_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue,
                      shutdown_event: multiprocessing.Event, worker_id: int):
    """Process predictions for CSV files"""
    logger = setup_logging()
    logger.info(f"Prediction worker {worker_id} started")

    # Create session for this worker
    session = create_session()

    try:
        while not shutdown_event.is_set():
            try:
                # Get task from input queue
                try:
                    task_item = input_queue.get(timeout=5)
                except queue.Empty:
                    continue

                task_id = task_item.task_id
                csv_file = task_item.file_path
                workspace = task_item.workspace

                logger.info(f"[{task_id}] Processing predictions")

                # Process predictions
                results = process_predictions_isolated(
                    csv_file, task_id, session, logger)

                # Send results to collector
                result_item = TaskItem(
                    task_id=task_id,
                    task_type="result",
                    data=results,
                    timestamp=datetime.now()
                )

                try:
                    result_queue.put(result_item, timeout=5)
                    logger.info(f"[{task_id}] Results sent to collector")
                except queue.Full:
                    logger.warning(f"[{task_id}] Result queue full")

                # Cleanup workspace
                cleanup_workspace(workspace)

            except Exception as e:
                logger.error(f"Prediction worker {worker_id} error: {e}")
                time.sleep(2)

    except KeyboardInterrupt:
        pass
    finally:
        if session:
            session.close()
        logger.info(f"Prediction worker {worker_id} shutting down")


def result_collector(result_queue: multiprocessing.Queue, stats: dict,
                     stats_lock: multiprocessing.Lock, shutdown_event: multiprocessing.Event):
    """Collect and aggregate results"""
    logger = setup_logging()
    logger.info("Result collector started")

    try:
        while not shutdown_event.is_set():
            try:
                # Get results
                try:
                    result_item = result_queue.get(timeout=5)
                except queue.Empty:
                    continue

                task_id = result_item.task_id
                results = result_item.data

                if results:
                    # Update global stats
                    with stats_lock:
                        stats['cycles_completed'] += 1
                        stats['total_flows_processed'] += results.get(
                            'total', 0)
                        stats['attacks_detected'] += results.get('attack', 0)
                        stats['errors'] += results.get('errors', 0)

                    # Log individual results
                    log_cycle_summary(task_id, results, logger)

            except Exception as e:
                logger.error(f"Result collector error: {e}")
                time.sleep(2)

    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Result collector shutting down")


def stats_reporter(stats: dict, stats_lock: multiprocessing.Lock,
                   shutdown_event: multiprocessing.Event):
    """Report system statistics periodically"""
    logger = setup_logging()
    logger.info("Stats reporter started")

    try:
        while not shutdown_event.is_set():
            if shutdown_event.wait(30):  # Report every 30 seconds
                break

            try:
                with stats_lock:
                    cycles = stats.get('cycles_completed', 0)
                    flows = stats.get('total_flows_processed', 0)
                    attacks = stats.get('attacks_detected', 0)
                    errors = stats.get('errors', 0)
                    start_time = stats.get('start_time', time.time())

                runtime = time.time() - start_time

                logger.info("=== SYSTEM STATISTICS ===")
                logger.info(f"Runtime: {runtime:.0f}s")
                logger.info(f"Cycles completed: {cycles}")
                logger.info(f"Total flows processed: {flows}")
                logger.info(f"Attacks detected: {attacks}")
                logger.info(f"Errors: {errors}")

                if cycles > 0:
                    logger.info(f"Average flows per cycle: {flows/cycles:.1f}")
                    logger.info(
                        f"Cycles per minute: {cycles/(runtime/60):.1f}")

                if flows > 0:
                    logger.info(f"Attack rate: {attacks/flows*100:.2f}%")

            except Exception as e:
                logger.error(f"Stats reporter error: {e}")

    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Stats reporter shutting down")


def create_session():
    """Create HTTP session with connection pooling"""
    session = requests.Session()

    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"]
    )

    adapter = HTTPAdapter(
        pool_connections=POOL_CONNECTIONS,
        pool_maxsize=POOL_MAXSIZE,
        max_retries=retry_strategy
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def create_isolated_workspace(task_id):
    """Create isolated workspace for each task"""
    workspace = os.path.join(TEMP_DIR, task_id)
    os.makedirs(workspace, exist_ok=True)
    return workspace


def cleanup_workspace(workspace):
    """Clean up workspace completely"""
    try:
        if os.path.exists(workspace):
            shutil.rmtree(workspace)
    except Exception as e:
        if logger:
            logger.error(f"Failed to cleanup workspace {workspace}: {e}")


def capture_traffic_isolated(task_id, workspace, logger):
    """Capture traffic with complete isolation from endpoint"""
    timestamp = get_timestamp()
    pcap_file = os.path.join(workspace, f"{task_id}_{timestamp}.pcap")

    logger.info(f"[{task_id}] Starting capture for {DURATION} seconds...")

    filter_expr = f"not (host {ENDPOINT_HOST} and port {ENDPOINT_PORT})"

    try:
        result = subprocess.run([
            "tshark", "-i", INTERFACE,
            "-a", f"duration:{DURATION}",
            "-f", filter_expr,
            "-F", "pcap",
            "-w", pcap_file,
            "-q"
        ], check=True, timeout=DURATION + 15, capture_output=True, text=True)

        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
            logger.info(
                f"[{task_id}] Capture successful: {os.path.getsize(pcap_file)} bytes")
            return pcap_file
        else:
            logger.warning(f"[{task_id}] Capture resulted in empty file")
            return None

    except subprocess.TimeoutExpired:
        logger.error(f"[{task_id}] Capture timeout")
        subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"],
                       capture_output=True, shell=True)
        return None
    except Exception as e:
        logger.error(f"[{task_id}] Capture error: {e}")
        return None


def convert_pcap_isolated(pcap_file, workspace, task_id, logger):
    """Convert PCAP to CSV with isolated CICFlowMeter instance"""
    logger.info(f"[{task_id}] Converting PCAP to CSV...")

    csv_output_dir = os.path.join(workspace, "csv_output")
    os.makedirs(csv_output_dir, exist_ok=True)

    try:
        result = subprocess.run([
            CFM_BAT, pcap_file, csv_output_dir
        ], shell=True, check=True, timeout=90, capture_output=True, text=True)

        csv_file = find_csv_file_in_dir(csv_output_dir)

        if csv_file and os.path.exists(csv_file):
            row_count = count_csv_rows(csv_file)
            logger.info(
                f"[{task_id}] CSV conversion successful: {row_count} flows")
            return csv_file
        else:
            logger.warning(f"[{task_id}] No CSV file generated")
            return None

    except subprocess.TimeoutExpired:
        logger.error(f"[{task_id}] CSV conversion timeout")
        return None
    except Exception as e:
        logger.error(f"[{task_id}] CSV conversion error: {e}")
        return None


def find_csv_file_in_dir(csv_dir):
    """Find CSV file in directory"""
    try:
        csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]
        if csv_files:
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
            return sum(1 for line in f) - 1
    except Exception:
        return 0


def process_predictions_isolated(csv_file, task_id, session, logger):
    """Process predictions with connection pooling and batching"""
    logger.info(f"[{task_id}] Processing predictions...")

    try:
        # Read CSV
        rows = []
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as file:
            reader = csv.DictReader(file)
            rows = list(reader)

        if not rows:
            logger.warning(f"[{task_id}] No data rows found in CSV")
            return {'total': 0, 'normal': 0, 'attack': 0, 'errors': 0}

        total_flows = len(rows)

        # Limit flows if necessary
        if total_flows > MAX_FLOWS_PER_CYCLE:
            step = total_flows // MAX_FLOWS_PER_CYCLE
            rows = rows[::step][:MAX_FLOWS_PER_CYCLE]

        logger.info(
            f"[{task_id}] Processing {len(rows)} flows (from {total_flows} total)")

        predictions = {
            'normal': 0,
            'attack': 0,
            'errors': 0,
            'total': len(rows),
            'original_total': total_flows
        }

        # Process with threading for I/O bound prediction requests
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_row = {
                executor.submit(send_prediction_request, row, task_id, session): i
                for i, row in enumerate(rows)
            }

            for future in as_completed(future_to_row, timeout=PREDICTION_TIMEOUT):
                try:
                    result = future.result(timeout=REQUEST_TIMEOUT)

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
                    logger.debug(f"[{task_id}] Prediction error: {e}")

        return predictions

    except Exception as e:
        logger.error(f"[{task_id}] Error processing predictions: {e}")
        return {'total': 0, 'normal': 0, 'attack': 0, 'errors': 1}


def send_prediction_request(row, task_id, session):
    """Send individual prediction request"""
    try:
        # Clean the row data
        cleaned_row = {}
        for k, v in row.items():
            if v is not None and v != '' and v != 'NaN':
                try:
                    cleaned_row[k] = float(v)
                except (ValueError, TypeError):
                    cleaned_row[k] = str(v)

        headers = {
            'Content-Type': 'application/json',
            'X-Task-ID': task_id,
            'Connection': 'keep-alive'
        }

        response = session.post(
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
                    'prediction': 'normal',
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
    except Exception as e:
        return {'success': False, 'error': f'Error: {str(e)[:50]}'}


def log_cycle_summary(task_id, predictions, logger):
    """Log cycle summary"""
    total = predictions['total']
    original_total = predictions.get('original_total', total)
    normal = predictions['normal']
    attack = predictions['attack']
    errors = predictions['errors']

    attack_percentage = (attack / total * 100) if total > 0 else 0

    logger.info(f"[{task_id}] RESULTS:")
    if original_total != total:
        logger.info(f"[{task_id}]   Flows: {total} (from {original_total})")
    else:
        logger.info(f"[{task_id}]   Flows: {total}")

    logger.info(f"[{task_id}]   Normal: {normal} ({normal/total*100:.1f}%)")
    logger.info(f"[{task_id}]   Attack: {attack} ({attack_percentage:.1f}%)")
    logger.info(f"[{task_id}]   Errors: {errors} ({errors/total*100:.1f}%)")

    if attack_percentage > 10:
        logger.warning(
            f"[{task_id}] [!] HIGH ATTACK TRAFFIC: {attack_percentage:.1f}%")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, initiating shutdown...")
    global ids_system
    if ids_system:
        ids_system.stop()
    sys.exit(0)


def main():
    """Main function"""
    global ids_system, logger

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and start the multiprocessing IDS
    ids_system = MultiprocessingIDS()

    try:
        ids_system.start()

        # Keep main process alive
        while not ids_system.shutdown_event.is_set():
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        ids_system.stop()
        logger.info("=== System shutdown complete ===")


if __name__ == "__main__":
    # Required for Windows multiprocessing
    multiprocessing.freeze_support()
    ids_system = None
    logger = None

    main()

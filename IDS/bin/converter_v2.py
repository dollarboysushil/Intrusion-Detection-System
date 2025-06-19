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

# Configuration
INTERFACE = "Ethernet"  # Change this to your real network interface
DURATION = 10  # Capture duration in seconds
ENDPOINT = "http://localhost:8000/predict/"
ENDPOINT_HOST = "localhost"
ENDPOINT_PORT = "8080"
CFM_BAT = "cfm.bat"
OUTPUT_DIR = "captures"
CSV_DIR = "csv_output"
TEMP_DIR = "temp_processing"
MAX_WORKERS = 4  # For ML prediction requests
CYCLE_COOLDOWN = 0.5  # Reduced since we're running in parallel
MAX_FLOWS_PER_CYCLE = 100
PREDICTION_TIMEOUT = 30
REQUEST_TIMEOUT = 5

# Queue configuration
CAPTURE_QUEUE_SIZE = 5  # Max captures waiting for processing
PROCESSING_QUEUE_SIZE = 3  # Max items in processing pipeline

# Setup logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [%(threadName)-15s] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parallel_intrusion_detection.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ensure directories exist
for directory in [OUTPUT_DIR, CSV_DIR, TEMP_DIR]:
    os.makedirs(directory, exist_ok=True)

# Global state management
shutdown_event = threading.Event()
capture_counter = 0
capture_counter_lock = threading.Lock()

# Communication queues
capture_queue = queue.Queue(maxsize=CAPTURE_QUEUE_SIZE)  # Completed captures waiting for processing
processing_queue = queue.Queue(maxsize=PROCESSING_QUEUE_SIZE)  # CSV files ready for ML prediction

class CaptureItem:
    """Represents a completed network capture"""
    def __init__(self, capture_id, pcap_file, workspace, timestamp):
        self.capture_id = capture_id
        self.pcap_file = pcap_file
        self.workspace = workspace
        self.timestamp = timestamp
        self.created_at = time.time()

class ProcessingItem:
    """Represents a CSV file ready for ML processing"""
    def __init__(self, capture_id, csv_file, workspace, flow_count):
        self.capture_id = capture_id
        self.csv_file = csv_file
        self.workspace = workspace
        self.flow_count = flow_count
        self.created_at = time.time()

def get_next_capture_id():
    """Thread-safe capture ID generation"""
    global capture_counter
    with capture_counter_lock:
        capture_counter += 1
        return f"capture_{capture_counter}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]}"

def create_isolated_workspace(capture_id):
    """Create isolated workspace for each capture"""
    workspace = os.path.join(TEMP_DIR, capture_id)
    os.makedirs(workspace, exist_ok=True)
    return workspace

def cleanup_workspace(workspace):
    """Clean up workspace completely"""
    try:
        if os.path.exists(workspace):
            shutil.rmtree(workspace)
            logger.debug(f"Cleaned up workspace: {workspace}")
    except Exception as e:
        logger.error(f"Failed to cleanup workspace {workspace}: {e}")

def continuous_packet_capture():
    """Continuously capture packets and queue them for processing"""
    logger.info("[CAPTURE] Starting continuous packet capture thread")
    consecutive_failures = 0
    max_consecutive_failures = 3
    
    while not shutdown_event.is_set():
        capture_id = get_next_capture_id()
        workspace = create_isolated_workspace(capture_id)
        
        try:
            logger.info(f"[CAPTURE] Starting {capture_id}")
            pcap_file = capture_traffic(capture_id, workspace)
            
            if pcap_file and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                # Create capture item
                capture_item = CaptureItem(capture_id, pcap_file, workspace, datetime.now())
                
                # Try to add to queue (non-blocking to prevent capture delays)
                try:
                    capture_queue.put(capture_item, timeout=1.0)
                    logger.info(f"[CAPTURE] {capture_id} queued for processing ({os.path.getsize(pcap_file)} bytes)")
                    consecutive_failures = 0
                except queue.Full:
                    logger.warning(f"[CAPTURE] Processing queue full, dropping {capture_id}")
                    cleanup_workspace(workspace)
                    consecutive_failures += 1
            else:
                logger.warning(f"[CAPTURE] {capture_id} failed - no valid capture")
                cleanup_workspace(workspace)
                consecutive_failures += 1
                
        except Exception as e:
            logger.error(f"[CAPTURE] Error in {capture_id}: {e}")
            cleanup_workspace(workspace)
            consecutive_failures += 1
        
        # Handle consecutive failures
        if consecutive_failures >= max_consecutive_failures:
            logger.error(f"[CAPTURE] Too many consecutive failures ({consecutive_failures}), pausing capture")
            time.sleep(30)  # Extended pause
            consecutive_failures = 0
        elif consecutive_failures > 0:
            time.sleep(5)  # Brief pause on failure
        
        # Small cooldown to prevent resource exhaustion
        time.sleep(CYCLE_COOLDOWN)

def capture_traffic(capture_id, workspace):
    """Capture network traffic to PCAP file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    pcap_file = os.path.join(workspace, f"{capture_id}_{timestamp}.pcap")
    
    # Enhanced filter to exclude endpoint traffic
    filter_expr = f"not (host {ENDPOINT_HOST} and port {ENDPOINT_PORT})"
    
    try:
        # Use subprocess with proper timeout handling
        process = subprocess.Popen([
            "tshark", "-i", INTERFACE,
            "-a", f"duration:{DURATION}",
            "-f", filter_expr,
            "-w", pcap_file,
            "-q"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Wait for completion with timeout
        try:
            stdout, stderr = process.communicate(timeout=DURATION + 10)
            
            if process.returncode == 0:
                if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                    return pcap_file
                else:
                    logger.warning(f"[CAPTURE] {capture_id} resulted in empty file")
                    return None
            else:
                logger.error(f"[CAPTURE] {capture_id} tshark error: {stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"[CAPTURE] {capture_id} timeout - terminating tshark")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            return None
            
    except Exception as e:
        logger.error(f"[CAPTURE] {capture_id} unexpected error: {e}")
        return None

def pcap_to_csv_processor():
    """Process captured PCAP files to CSV format"""
    logger.info("[CONVERTER] Starting PCAP to CSV processor thread")
    
    while not shutdown_event.is_set():
        try:
            # Get next capture to process
            try:
                capture_item = capture_queue.get(timeout=5.0)
            except queue.Empty:
                continue
            
            try:
                logger.info(f"[CONVERTER] Processing {capture_item.capture_id}")
                csv_file = convert_pcap_to_csv(capture_item)
                
                if csv_file:
                    flow_count = count_csv_rows(csv_file)
                    processing_item = ProcessingItem(
                        capture_item.capture_id, 
                        csv_file, 
                        capture_item.workspace, 
                        flow_count
                    )
                    
                    # Queue for ML processing
                    try:
                        processing_queue.put(processing_item, timeout=2.0)
                        logger.info(f"[CONVERTER] {capture_item.capture_id} converted ({flow_count} flows)")
                    except queue.Full:
                        logger.warning(f"[CONVERTER] ML queue full, dropping {capture_item.capture_id}")
                        cleanup_workspace(capture_item.workspace)
                else:
                    logger.warning(f"[CONVERTER] {capture_item.capture_id} conversion failed")
                    cleanup_workspace(capture_item.workspace)
                    
            except Exception as e:
                logger.error(f"[CONVERTER] Error processing {capture_item.capture_id}: {e}")
                cleanup_workspace(capture_item.workspace)
            finally:
                capture_queue.task_done()
                
        except Exception as e:
            logger.error(f"[CONVERTER] Unexpected error: {e}")
            time.sleep(1)

def convert_pcap_to_csv(capture_item):
    """Convert PCAP to CSV using CICFlowMeter"""
    csv_output_dir = os.path.join(capture_item.workspace, "csv_output")
    os.makedirs(csv_output_dir, exist_ok=True)
    
    try:
        result = subprocess.run([
            CFM_BAT, capture_item.pcap_file, csv_output_dir
        ], shell=True, check=True, timeout=60, capture_output=True, text=True)
        
        # Find generated CSV file
        csv_file = find_csv_file_in_dir(csv_output_dir)
        
        if csv_file and os.path.exists(csv_file):
            return csv_file
        else:
            logger.warning(f"[CONVERTER] No CSV generated for {capture_item.capture_id}")
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"[CONVERTER] {capture_item.capture_id} conversion timeout")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"[CONVERTER] {capture_item.capture_id} CFM error: {e}")
        return None
    except Exception as e:
        logger.error(f"[CONVERTER] {capture_item.capture_id} unexpected error: {e}")
        return None

def find_csv_file_in_dir(csv_dir):
    """Find most recent CSV file in directory"""
    try:
        csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]
        if csv_files:
            csv_files.sort(key=lambda x: os.path.getmtime(os.path.join(csv_dir, x)), reverse=True)
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

def ml_prediction_processor():
    """Process CSV files through ML model"""
    logger.info("[ML] Starting ML prediction processor thread")
    
    while not shutdown_event.is_set():
        try:
            # Get next item to process
            try:
                processing_item = processing_queue.get(timeout=5.0)
            except queue.Empty:
                continue
            
            try:
                logger.info(f"[ML] Processing {processing_item.capture_id}")
                success = process_ml_predictions(processing_item)
                
                if success:
                    logger.info(f"[ML] {processing_item.capture_id} completed successfully")
                else:
                    logger.warning(f"[ML] {processing_item.capture_id} processing failed")
                    
            except Exception as e:
                logger.error(f"[ML] Error processing {processing_item.capture_id}: {e}")
            finally:
                # Always cleanup workspace when done
                cleanup_workspace(processing_item.workspace)
                processing_queue.task_done()
                
        except Exception as e:
            logger.error(f"[ML] Unexpected error: {e}")
            time.sleep(1)

def process_ml_predictions(processing_item):
    """Process ML predictions for a CSV file"""
    try:
        # Read CSV with error handling
        rows = []
        with open(processing_item.csv_file, 'r', encoding='utf-8', errors='ignore') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
        
        if not rows:
            logger.warning(f"[ML] {processing_item.capture_id} no data rows found")
            return True  # Not an error condition
        
        total_flows = len(rows)
        
        # Limit flows to prevent bottleneck
        if total_flows > MAX_FLOWS_PER_CYCLE:
            logger.info(f"[ML] {processing_item.capture_id} limiting flows from {total_flows} to {MAX_FLOWS_PER_CYCLE}")
            step = total_flows // MAX_FLOWS_PER_CYCLE
            rows = rows[::step][:MAX_FLOWS_PER_CYCLE]
        
        logger.info(f"[ML] {processing_item.capture_id} processing {len(rows)} flows")
        
        # Track predictions
        predictions = {
            'normal': 0,
            'attack': 0,
            'errors': 0,
            'total': len(rows),
            'original_total': total_flows
        }
        
        # Process with timeout
        start_time = time.time()
        completed_requests = 0
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_row = {
                executor.submit(send_prediction_request, row, processing_item.capture_id): i 
                for i, row in enumerate(rows)
            }
            
            for future in as_completed(future_to_row, timeout=PREDICTION_TIMEOUT):
                if time.time() - start_time > PREDICTION_TIMEOUT:
                    logger.warning(f"[ML] {processing_item.capture_id} prediction timeout reached")
                    for remaining_future in future_to_row:
                        if not remaining_future.done():
                            remaining_future.cancel()
                    break
                
                try:
                    result = future.result(timeout=1)
                    completed_requests += 1
                    
                    if result.get('success'):
                        prediction = result.get('prediction', 'unknown').lower()
                        if 'attack' in prediction or 'malicious' in prediction:
                            predictions['attack'] += 1
                        else:
                            predictions['normal'] += 1
                    else:
                        predictions['errors'] += 1
                        
                    if completed_requests % 25 == 0:
                        logger.debug(f"[ML] {processing_item.capture_id} progress: {completed_requests}/{len(rows)}")
                        
                except Exception as e:
                    predictions['errors'] += 1
        
        # Log summary
        log_prediction_summary(processing_item.capture_id, predictions)
        
        # Success if we completed at least 50% of requests
        success_rate = completed_requests / len(rows) if len(rows) > 0 else 0
        return success_rate >= 0.5
        
    except Exception as e:
        logger.error(f"[ML] {processing_item.capture_id} error: {e}")
        return False

def send_prediction_request(row, capture_id):
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
            'X-Capture-ID': capture_id
        }
        
        response = requests.post(
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
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Request error: {str(e)[:50]}'}
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)[:50]}'}

def log_prediction_summary(capture_id, predictions):
    """Log prediction results summary"""
    total = predictions['total']
    original_total = predictions.get('original_total', total)
    normal = predictions['normal']
    attack = predictions['attack']
    errors = predictions['errors']
    
    attack_percentage = (attack / total * 100) if total > 0 else 0
    
    logger.info(f"[ML] {capture_id} SUMMARY:")
    if original_total != total:
        logger.info(f"[ML] {capture_id}   Original flows: {original_total} (processed: {total})")
    else:
        logger.info(f"[ML] {capture_id}   Total flows: {total}")
    logger.info(f"[ML] {capture_id}   Normal: {normal} ({normal/total*100:.1f}%)")
    logger.info(f"[ML] {capture_id}   Attack: {attack} ({attack_percentage:.1f}%)")
    logger.info(f"[ML] {capture_id}   Errors: {errors} ({errors/total*100:.1f}%)")
    
    # Alert on high attack percentage
    if attack_percentage > 10:
        logger.warning(f"[ML] {capture_id} [!] HIGH ATTACK TRAFFIC DETECTED: {attack_percentage:.1f}%")
    else:
        logger.info(f"[ML] {capture_id} [OK] Normal traffic levels")

def system_monitor():
    """Monitor system health and perform maintenance"""
    logger.info("[MONITOR] Starting system monitor thread")
    
    while not shutdown_event.is_set():
        try:
            # Log queue status
            capture_queue_size = capture_queue.qsize()
            processing_queue_size = processing_queue.qsize()
            
            if capture_queue_size > 0 or processing_queue_size > 0:
                logger.info(f"[MONITOR] Queue status - Capture: {capture_queue_size}, Processing: {processing_queue_size}")
            
            # Check disk space
            check_disk_space()
            
            # Cleanup old files
            cleanup_old_files()
            
            # Cleanup zombie processes
            cleanup_zombie_processes()
            
            # Wait before next check
            shutdown_event.wait(60)  # Check every minute
            
        except Exception as e:
            logger.error(f"[MONITOR] Error: {e}")
            shutdown_event.wait(30)

def check_disk_space():
    """Check available disk space"""
    try:
        total, used, free = shutil.disk_usage(".")
        free_gb = free // (1024**3)
        
        if free_gb < 1:
            logger.warning(f"[MONITOR] Low disk space: {free_gb}GB free")
            emergency_cleanup()
            
    except Exception as e:
        logger.error(f"[MONITOR] Disk space check error: {e}")

def cleanup_old_files():
    """Cleanup old files from directories"""
    directories_to_clean = [OUTPUT_DIR, CSV_DIR, TEMP_DIR]
    
    for directory in directories_to_clean:
        if not os.path.exists(directory):
            continue
            
        try:
            files = []
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath):
                        files.append((filepath, os.path.getmtime(filepath)))
            
            files.sort(key=lambda x: x[1], reverse=True)
            
            # Keep only the 20 most recent files
            if len(files) > 20:
                for filepath, _ in files[20:]:
                    try:
                        os.remove(filepath)
                        logger.debug(f"[MONITOR] Cleaned up old file: {filepath}")
                    except Exception:
                        pass
                        
            # Remove empty directories
            for root, dirs, filenames in os.walk(directory, topdown=False):
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    try:
                        if not os.listdir(dirpath):
                            os.rmdir(dirpath)
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.error(f"[MONITOR] Error cleaning {directory}: {e}")

def emergency_cleanup():
    """Emergency cleanup when disk space is low"""
    logger.warning("[MONITOR] Performing emergency cleanup...")
    
    for directory in [OUTPUT_DIR, CSV_DIR, TEMP_DIR]:
        try:
            if os.path.exists(directory):
                shutil.rmtree(directory)
                os.makedirs(directory, exist_ok=True)
                logger.info(f"[MONITOR] Emergency cleanup completed for {directory}")
        except Exception as e:
            logger.error(f"[MONITOR] Emergency cleanup failed for {directory}: {e}")

def cleanup_zombie_processes():
    """Kill any zombie processes"""
    try:
        subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"], 
                      capture_output=True, shell=True)
        
        result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq java.exe"], 
                               capture_output=True, text=True, shell=True)
        
        if "java.exe" in result.stdout:
            subprocess.run(["taskkill", "/F", "/IM", "java.exe"], 
                          capture_output=True, shell=True)
            
    except Exception as e:
        logger.error(f"[MONITOR] Process cleanup error: {e}")

def main():
    """Main function with parallel pipeline management"""
    logger.info("=== Starting Parallel Network Intrusion Detection System ===")
    logger.info(f"Interface: {INTERFACE}")
    logger.info(f"Capture duration: {DURATION} seconds")
    logger.info(f"Endpoint: {ENDPOINT}")
    logger.info(f"Filtering traffic to {ENDPOINT_HOST}:{ENDPOINT_PORT}")
    logger.info(f"Max capture queue size: {CAPTURE_QUEUE_SIZE}")
    logger.info(f"Max processing queue size: {PROCESSING_QUEUE_SIZE}")
    
    # Start all worker threads
    threads = []
    
    # Packet capture thread (continuous)
    capture_thread = threading.Thread(
        target=continuous_packet_capture, 
        name="CaptureWorker",
        daemon=False
    )
    threads.append(capture_thread)
    
    # PCAP to CSV conversion thread
    converter_thread = threading.Thread(
        target=pcap_to_csv_processor, 
        name="ConverterWorker",
        daemon=False
    )
    threads.append(converter_thread)
    
    # ML prediction thread
    ml_thread = threading.Thread(
        target=ml_prediction_processor, 
        name="MLWorker",
        daemon=False
    )
    threads.append(ml_thread)
    
    # System monitor thread
    monitor_thread = threading.Thread(
        target=system_monitor, 
        name="MonitorWorker",
        daemon=True
    )
    threads.append(monitor_thread)
    
    try:
        # Start all threads
        for thread in threads:
            thread.start()
            logger.info(f"Started {thread.name}")
        
        logger.info("=== All workers started - system is running ===")
        
        # Wait for keyboard interrupt
        while not shutdown_event.is_set():
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutdown requested by user")
                break
                
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        logger.info("=== Shutting down system ===")
        shutdown_event.set()
        
        # Wait for non-daemon threads to finish
        for thread in threads:
            if not thread.daemon and thread.is_alive():
                logger.info(f"Waiting for {thread.name} to finish...")
                thread.join(timeout=10)
                if thread.is_alive():
                    logger.warning(f"{thread.name} did not finish gracefully")
        
        # Final cleanup
        cleanup_zombie_processes()
        cleanup_old_files()
        
        logger.info("=== Parallel Network Intrusion Detection System Stopped ===")

if __name__ == "__main__":
    main()
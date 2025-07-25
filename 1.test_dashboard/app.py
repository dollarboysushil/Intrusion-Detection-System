# app.py
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import os
import logging

# --- Configuration ---
# Update this path to the absolute path of your db.sqlite3 file
# Make sure this path is correct for your system
DB_PATH = r'D:\8th sem\Intrusion-Detection-System\Network_Anomaly_Detection_System1\NADS_Server\db.sqlite3'

# Configure logging for debugging
logging.basicConfig(level=logging.INFO)  # Use INFO or DEBUG for more details
logger = logging.getLogger(__name__)

app = Flask(__name__)
# CORS is helpful if you ever need to serve HTML from a different origin
# For this setup (Flask serves HTML), it's not strictly necessary but good practice.
CORS(app)


def get_db_connection():
    """Establishes a connection to the SQLite database."""
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found at {DB_PATH}")
        raise FileNotFoundError(f"Database file not found at {DB_PATH}")

    try:
        conn = sqlite3.connect(DB_PATH)
        # Allows accessing columns by name (e.g., row['attack'])
        conn.row_factory = sqlite3.Row
        logger.info(f"Successfully connected to database at {DB_PATH}")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Error connecting to database: {e}")
        raise


@app.route('/')
def index():
    """Serve the main dashboard HTML file."""
    logger.info("Serving dashboard.html")
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')

# --- API Endpoints ---


@app.route('/api/dashboard-data/')
def dashboard_data():
    """
    Provides data for the 'Attack Trends (Last 5 Minutes)' chart.
    This implementation follows the request for 5 minutes / 30 sec intervals.
    """
    logger.info("API /api/dashboard-data/ called")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # --- Fetch data for the main line chart (last 5 mins, 30-sec intervals) ---
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=5)

        intervals = []
        current_time = start_time
        while current_time < end_time:
            interval_end = current_time + timedelta(seconds=30)
            intervals.append((current_time, interval_end))
            current_time = interval_end

        # Define attack types to track (MATCH THESE EXACTLY TO YOUR DB VALUES)
        # Based on your request and common names
        attack_types_config = [
            {'label': 'Normal', 'db_name': 'Normal',
                'color': '#2ecc71'},  # Added 'Normal'
            {'label': 'DDOS', 'db_name': 'DDOS',
                'color': '#e74c3c'},  # Assuming 'DDOS' in DB
            {'label': 'PortScan', 'db_name': 'PortScan',
                'color': '#f39c12'},  # Assuming 'PortScan' in DB
            {'label': 'BruteForce', 'db_name': 'BruteForce', 'color': '#9b59b6'},
            {'label': 'SqlInjection', 'db_name': 'SqlInjection',
                'color': '#1abc9c'},  # Added
        ]

        # Initialize data structure for Chart.js
        chart_data = {
            'labels': [],
            'datasets': []
        }

        # Create datasets based on the configuration
        for attack_config in attack_types_config:
            chart_data['datasets'].append({
                'label': attack_config['label'],
                'data': [],
                'borderColor': attack_config['color'],
                'backgroundColor': f"rgba({int(attack_config['color'][1:3], 16)}, {int(attack_config['color'][3:5], 16)}, {int(attack_config['color'][5:7], 16)}, 0.1)",
                'tension': 0.4
            })

        # Query database for each interval and attack type
        for start, end in intervals:
            start_str = start.strftime('%Y-%m-%d %H:%M:%S')
            # Full datetime for query
            end_str = end.strftime('%Y-%m-%d %H:%M:%S')

            # Label with just the end time (hour:minute:second) for the x-axis
            chart_data['labels'].append(end.strftime('%H:%M:%S'))

            for dataset in chart_data['datasets']:
                attack_label = dataset['label']
                db_attack_name = next(
                    (item['db_name'] for item in attack_types_config if item['label'] == attack_label), attack_label)

                cursor.execute("""
                    SELECT COUNT(*) FROM dashboard_attacklog
                    WHERE timestamp >= ? AND timestamp < ? AND attack = ?
                """, (start_str, end_str, db_attack_name))

                result_row = cursor.fetchone()
                count = result_row[0] if result_row else 0

                dataset['data'].append(count)

        conn.close()
        logger.info("Successfully fetched attack trends data")
        return jsonify(chart_data)

    except FileNotFoundError as e:
        logger.error(f"Database file error: {e}")
        return jsonify({'error': str(e)}), 500
    except sqlite3.Error as e:
        logger.error(f"Database query error: {e}")
        if 'conn' in locals():
            conn.close()
        return jsonify({'error': 'Database query failed'}), 500
    except Exception as e:
        logger.error(
            f"Unexpected error in /api/dashboard-data/: {e}", exc_info=True)
        if 'conn' in locals():
            conn.close()
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500


@app.route('/api/attack-distribution/')
def attack_distribution():
    """Provides data for the 'Attack Type Distribution' doughnut chart (last 5 minutes)."""
    logger.info("API /api/attack-distribution/ called")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        time_threshold = (datetime.now() - timedelta(minutes=5)
                          ).strftime('%Y-%m-%d %H:%M:%S')

        cursor.execute("""
            SELECT attack, COUNT(*) as count FROM dashboard_attacklog
            WHERE timestamp >= ?
            GROUP BY attack
        """, (time_threshold,))

        results = cursor.fetchall()
        conn.close()

        # Prepare data for Chart.js doughnut
        labels = [row['attack'] for row in results]
        data = [row['count'] for row in results]

        # Define colors for the distribution chart, including new types
        background_colors = []
        for label in labels:
            if label.lower() == 'normal':
                background_colors.append('#2ecc71')  # Green
            elif label.lower() == 'ddos':
                background_colors.append('#e74c3c')  # Red
            elif label.lower() in ['portscan', 'port scan']:
                background_colors.append('#f39c12')  # Orange
            elif label.lower() == 'bruteforce':
                background_colors.append('#9b59b6')  # Purple
            elif label.lower() == 'sqlinjection':
                background_colors.append('#1abc9c')  # Turquoise
            else:
                # Default color for any other attack type
                background_colors.append('#3498db')  # Blue

        response_data = {
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': background_colors
            }]
        }
        logger.info("Successfully fetched attack distribution data")
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error fetching attack distribution: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch distribution data'}), 500


@app.route('/api/recent-alerts/')
def recent_alerts():
    """Provides data for the 'Recent Alerts' table (last 8 alerts)."""
    logger.info("API /api/recent-alerts/ called")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, host_ip, destination_ip, attack FROM dashboard_attacklog
            ORDER BY timestamp DESC
            LIMIT 8
        """)

        rows = cursor.fetchall()
        conn.close()

        alerts = []
        for row in rows:
            attack_type = row['attack']
            # Simple severity mapping based on attack type
            if attack_type.lower() in ['ddos']:
                severity = 'high'
            elif attack_type.lower() in ['portscan', 'port scan', 'sqlinjection', 'bruteforce']:
                severity = 'medium'
            elif attack_type.lower() == 'normal':
                severity = 'low'
            else:
                severity = 'low'

            alerts.append({
                'timestamp': row['timestamp'],
                'sourceIp': row['host_ip'],
                'destIp': row['destination_ip'],
                'protocol': 'TCP/IP',  # Placeholder, derive from DB if available
                'attackType': attack_type,
                'severity': severity
            })
        logger.info("Successfully fetched recent alerts data")
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error fetching recent alerts: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch alerts'}), 500


@app.route('/api/system-status/')
def system_status():
    """Provides mock data for system status (CPU, RAM, Disk)."""
    logger.info("API /api/system-status/ called")
    import random
    mock_data = {
        'cpu': random.randint(30, 60),
        'ram': random.randint(50, 75),
        'disk': random.randint(20, 40)
    }
    logger.info("Successfully generated system status data")
    return jsonify(mock_data)


@app.route('/api/summary-metrics/')
def summary_metrics():
    """Provides data for the summary metric cards (counts from last hour)."""
    logger.info("API /api/summary-metrics/ called")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        time_threshold = (datetime.now() - timedelta(hours=1)
                          ).strftime('%Y-%m-%d %H:%M:%S')

        # Total Flows
        cursor.execute(
            "SELECT COUNT(*) FROM dashboard_attacklog WHERE timestamp >= ?", (time_threshold,))
        total_flows = cursor.fetchone()[0]

        # DDoS Count
        cursor.execute(
            "SELECT COUNT(*) FROM dashboard_attacklog WHERE timestamp >= ? AND attack = 'DDOS'", (time_threshold,))
        ddos_count = cursor.fetchone()[0]

        # Port Scan Count
        cursor.execute(
            "SELECT COUNT(*) FROM dashboard_attacklog WHERE timestamp >= ? AND attack = 'PortScan'", (time_threshold,))
        portscan_count = cursor.fetchone()[0]

        # SQL Injection Count
        cursor.execute(
            "SELECT COUNT(*) FROM dashboard_attacklog WHERE timestamp >= ? AND attack = 'SqlInjection'", (time_threshold,))
        sqlinjection_count = cursor.fetchone()[0]

        # BruteForce Count (for the "OTHER ATTACKS" card which now shows BruteForce)
        cursor.execute(
            "SELECT COUNT(*) FROM dashboard_attacklog WHERE timestamp >= ? AND attack = 'BruteForce'", (time_threshold,))
        bruteforce_count = cursor.fetchone()[0]

        # Normal Count (if needed elsewhere)
        cursor.execute(
            "SELECT COUNT(*) FROM dashboard_attacklog WHERE timestamp >= ? AND attack = 'Normal'", (time_threshold,))
        normal_count = cursor.fetchone()[0]

        conn.close()

        response_data = {
            'totalFlows': total_flows,
            'ddosCount': ddos_count,
            'portscanCount': portscan_count,
            'sqlInjectionCount': sqlinjection_count,
            'bruteforceCount': bruteforce_count,  # Send BruteForce count
            # 'otherAttacksCount': other_count, # Removed as not needed
            'normalCount': normal_count
        }
        logger.info("Successfully fetched summary metrics data")
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error fetching summary metrics: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch metrics'}), 500


if __name__ == '__main__':
    # Check if DB file exists before starting
    if not os.path.exists(DB_PATH):
        print(f"CRITICAL ERROR: Database file not found at {DB_PATH}")
        print("Please check the DB_PATH variable in app.py")
        exit(1)

    print(f"Starting Flask server...")
    print(f"Looking for database at: {DB_PATH}")
    print(f"Access the dashboard at: http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)

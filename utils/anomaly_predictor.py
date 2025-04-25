import os
import json
import time
import threading
from datetime import datetime
from sklearn.ensemble import IsolationForest
from collections import defaultdict
import numpy as np
import requests

LOG_DIR = r"C:\Users\Administrator\OneDrive\Desktop\demo\logs"
OUTPUT_TXT_FILE = r"C:\Users\Administrator\OneDrive\Desktop\demo\utils\predictive_analysis_result.txt"

last_seen = {}
api_error_history = defaultdict(lambda: {"total": 0, "errors": 0})
server_health = {}  # Track server health status

# ---------------- Utility ------------------

def read_latest_log(file_path):
    try:
        with open(file_path, 'r') as f:
            lines = f.read().strip().split("\n")
            if lines:
                return json.loads(lines[-1])
    except Exception as e:
        print(f"[Read Error] Failed to read {file_path}: {e}")
    return None

def update_api_error_stats(api_name, environment, success):
    key = f"{api_name}|{environment}"
    api_error_history[key]["total"] += 1
    if not success:
        api_error_history[key]["errors"] += 1

def get_error_rate(api_name, environment):
    key = f"{api_name}|{environment}"
    stats = api_error_history[key]
    if stats["total"] == 0:
        return 0.0
    return stats["errors"] / stats["total"]

# ---------------- ALERTING ------------------

def trigger_alert(api, env, rate, server_id=None):
    alert_msg = f"[ALERT] 🚨 High error rate detected! API: '{api}' | Environment: '{env}' | Error Rate: {rate:.2f}"
    if server_id:
        alert_msg += f" | Server: {server_id}"
    print(alert_msg)
    
    # Log alert to output file for visibility
    alert_data = {
        "alert_type": "high_error_rate",
        "api": api,
        "environment": env,
        "error_rate": rate,
        "server_id": server_id,
        "timestamp": datetime.utcnow().isoformat(),
        "message": alert_msg
    }
    write_predictive_output(alert_data)
    
    # Update server health status
    if server_id:
        server_health[server_id] = "degraded"
        print(f"[Server Status] Marking server {server_id} as degraded")

# ---------------- Anomaly Detection ------------------

def extract_features(log_data):
    try:
        return [
            log_data["response"]["time_ms"],
            log_data["response"]["status_code"],
            int(log_data["security"]["mfa_used"]),
            1 if log_data["security"]["ip_reputation"] == "suspicious" else 0,
            log_data["security"]["rate_limit"]["remaining"]
        ]
    except KeyError as e:
        print(f"[Feature Error] Missing field: {e}")
        return [0, 0, 0, 0, 0]  # fallback

def detect_anomaly(log_data):
    features = extract_features(log_data)
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit([features])  # For production: maintain historical sample buffer
    prediction = clf.predict([features])[0]
    return prediction == -1

# ---------------- Predictive Analysis ------------------

def run_predictive_analysis(log_data):
    impact_score = 0
    reasons = []

    op = log_data.get('operation', {})
    sec = log_data.get('security', {})
    meta = log_data.get('meta', {})
    tracing = log_data.get('tracing', {})
    resp = log_data.get('response', {})
    
    # Extract server information
    server_id = tracing.get('server_id') or log_data.get('server_context', {}).get('server_id')
    previous_server_id = tracing.get('previous_server_id')

    api_type = op.get('type', 'unknown')
    environment = meta.get('environment', 'unknown')
    success = op.get('success', True)
    status_code = resp.get('status_code', 200)
    rate_remaining = sec.get('rate_limit', {}).get('remaining', 100)
    mfa_used = sec.get('mfa_used', True)
    ip_rep = sec.get('ip_reputation', 'normal')
    retry_count = meta.get('retry_count', 0)
    session_failures = tracing.get('session_failures', 0)

    if not success:
        impact_score += 3
        reasons.append("API call failed")

    if status_code >= 500:
        impact_score += 2
        reasons.append(f"Server error ({status_code})")

    if not mfa_used:
        impact_score += 1
        reasons.append("MFA not used")

    if ip_rep == "suspicious":
        impact_score += 2
        reasons.append("Suspicious IP")

    if rate_remaining < 10:
        impact_score += 1
        reasons.append("Rate limit low")

    if retry_count > 2:
        impact_score += 1
        reasons.append("Excessive retries")

    if session_failures > 1:
        impact_score += 1
        reasons.append("Repeated session failures")

    if environment in ["multi-cloud", "hybrid"]:
        impact_score += 1
        reasons.append(f"Complex infra: {environment}")
        
    # Check if server is already flagged as degraded
    if server_id and server_id in server_health and server_health[server_id] == "degraded":
        impact_score += 3
        reasons.append(f"Server {server_id} is already degraded")

    # Check historical error rate
    err_rate = get_error_rate(api_type, environment)
    if err_rate > 0.25:
        impact_score += 2
        reasons.append(f"High historical error rate: {err_rate:.2f}")

    # ----------- Alert condition -----------
    if err_rate > 0.3:
        trigger_alert(api_type, environment, err_rate, server_id)
    # ---------------------------------------

    if impact_score >= 7:
        impact = "High Impact"
    elif impact_score >= 4:
        impact = "Moderate Impact"
    else:
        impact = "Low Impact"

    return {
        "impact": impact,
        "impact_score": impact_score,
        "reasons": reasons,
        "error_rate": err_rate,
        "api": api_type,
        "environment": environment,
        "timestamp": datetime.utcnow().isoformat(),
        "historical_error_rate": err_rate,
        "server_id": server_id,
        "previous_server_id": previous_server_id,
        "tracing": tracing  # Include tracing data for socket monitoring
    }

# ---------------- Log Output Writer ------------------

def convert_json_safe(obj):
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def write_predictive_output(data):
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(OUTPUT_TXT_FILE), exist_ok=True)
        
        with open(OUTPUT_TXT_FILE, 'a') as f:
            json_str = json.dumps(data, indent=2, default=convert_json_safe)
            f.write(json_str)
            f.write("\n\n")
        print(f"[Write Success] Written to {OUTPUT_TXT_FILE}")
    except Exception as e:
        print(f"[Write Error] Failed to write output: {e}")

# ---------------- Real-time Socket Monitor ------------------

def ping_api(api_url):
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            print(f"[Ping Success] API {api_url} is running")
            return True
        else:
            print(f"[Ping Failure] API {api_url} responded with status {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"[Ping Error] Failed to reach {api_url}: {e}")
        return False

def analyze_server_impact(server_id, anomalous_api, raw_logs):
    """Analyze impact of a server failure on other APIs"""
    
    # Log server anomaly detection
    server_impact_data = {
        "analysis_type": "server_impact",
        "server_id": server_id,
        "triggering_api": anomalous_api,
        "timestamp": datetime.utcnow().isoformat(),
        "affected_apis": [],
        "message": f"Analyzing impact of failure on server {server_id} triggered by API {anomalous_api}"
    }
    
    # Find other APIs running on the same server
    for raw in raw_logs:
        if not raw.strip():
            continue
            
        try:
            log = json.loads(raw)
            log_server_id = log.get("server_id")
            
            if log_server_id == server_id and log.get("api") != anomalous_api:
                server_impact_data["affected_apis"].append({
                    "api": log.get("api"),
                    "environment": log.get("environment"),
                    "impact": log.get("impact"),
                    "impact_score": log.get("impact_score")
                })
        except json.JSONDecodeError:
            continue
    
    # Write server impact analysis
    write_predictive_output(server_impact_data)
    return server_impact_data["affected_apis"]

def check_cross_server_impact(previous_server_id, anomalous_api):
    """Check impact on APIs running on a different server"""
    if not previous_server_id:
        return
        
    ping_result = ping_api(f"http://api_server_{previous_server_id}/health")
    
    # Log cross-server analysis
    cross_server_data = {
        "analysis_type": "cross_server_check",
        "primary_server_with_issue": anomalous_api.split("_")[0] if "_" in anomalous_api else "unknown",
        "checked_server_id": previous_server_id,
        "timestamp": datetime.utcnow().isoformat(),
        "health_check_passed": ping_result,
        "message": f"Cross-server health check for server {previous_server_id} after anomaly on {anomalous_api}"
    }
    
    # Write cross-server analysis
    write_predictive_output(cross_server_data)

def process_log_files():
    """Process log files and generate predictions"""
    new_predictions = False
    
    try:
        # Check if LOG_DIR exists
        if not os.path.exists(LOG_DIR):
            print(f"[Warning] Log directory {LOG_DIR} does not exist. Creating it...")
            os.makedirs(LOG_DIR, exist_ok=True)
            return new_predictions
            
        log_files = [os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.endswith('.json')]
        
        # No log files found
        if not log_files:
            return new_predictions
            
        for log_file in log_files:
            # Check if file was already processed or if it's been updated
            file_mtime = os.path.getmtime(log_file)
            if log_file in last_seen and last_seen[log_file] >= file_mtime:
                continue
                
            # Update last seen time
            last_seen[log_file] = file_mtime
            
            # Read the log file
            log_data = read_latest_log(log_file)
            if not log_data:
                continue
                
            # Update error statistics
            api_name = log_data.get('operation', {}).get('type', 'unknown')
            
            # Get environment - check in multiple places
            environment = log_data.get('meta', {}).get('environment', 'unknown')
            if environment == 'unknown':
                # Try to get from service info
                for key in log_data:
                    if key.endswith('_service') and isinstance(log_data[key], dict):
                        environment = log_data[key].get('environment', environment)
                        break
            
            success = log_data.get('operation', {}).get('success', True)
            update_api_error_stats(api_name, environment, success)
            
            # Run analysis
            analysis_result = run_predictive_analysis(log_data)
            
            # Write output
            write_predictive_output(analysis_result)
            print(f"[Analysis] Processed log file: {log_file}")
            new_predictions = True
            
    except Exception as e:
        print(f"[Process Error] Error processing log files: {e}")
        
    return new_predictions

def monitor_logs(socketio):
    seen_anomalies = set()

    print("[Monitor] Real-time log socket monitoring started...")
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_TXT_FILE), exist_ok=True)
    
    # Create empty output file if it doesn't exist
    if not os.path.exists(OUTPUT_TXT_FILE):
        with open(OUTPUT_TXT_FILE, 'w') as f:
            f.write("")
    
    while True:
        try:
            # Process new log files
            new_data = process_log_files()

            # Check for anomalies in the output file
            if os.path.exists(OUTPUT_TXT_FILE) and os.path.getsize(OUTPUT_TXT_FILE) > 0:
                with open(OUTPUT_TXT_FILE, 'r') as f:
                    raw_logs = f.read().strip().split("\n\n")

                for raw in raw_logs:
                    if raw.strip():
                        try:
                            log = json.loads(raw)
                            
                            # Skip entries that aren't analysis results
                            if "analysis_type" in log:
                                continue
                                
                            if log.get("historical_error_rate", 0) > 0.5 or log.get("impact") == "High Impact":
                                anomaly_id = f"{log['api']}_{log['timestamp']}"
                                if anomaly_id not in seen_anomalies:
                                    seen_anomalies.add(anomaly_id)
                                    print(f"[New Anomaly] Detected anomaly in {log['api']}")

                                    # Check if the anomaly is related to a specific server
                                    server_id = log.get("server_id")
                                    if server_id:
                                        print(f"[Server Anomaly] API {log['api']} on server {server_id} has failed")
                                        
                                        # Perform detailed server impact analysis and log it
                                        affected_apis = analyze_server_impact(server_id, log['api'], raw_logs)
                                        
                                        # Mark other APIs on the same server as anomalous
                                        for affected in affected_apis:
                                            socketio.emit('new_anomaly', {
                                                "api": affected["api"],
                                                "env": affected.get("environment", "unknown"),
                                                "error_rate": log.get("historical_error_rate", 0),
                                                "impact": affected.get("impact", "Unknown"),
                                                "server_id": server_id,
                                                "timestamp": log["timestamp"]
                                            })
                                    
                                    # Check APIs on different servers
                                    previous_server_id = log.get("previous_server_id")
                                    if previous_server_id and previous_server_id != server_id:
                                        print(f"[Cross-Server Check] Checking health of related API server {previous_server_id}")
                                        check_cross_server_impact(previous_server_id, log['api'])

                                    # Emit main anomaly
                                    socketio.emit('new_anomaly', {
                                        "api": log["api"],
                                        "env": log.get("environment", "unknown"),
                                        "error_rate": log["historical_error_rate"],
                                        "impact": log.get("impact", "Unknown"),
                                        "server_id": server_id,
                                        "timestamp": log["timestamp"]
                                    })
                        except Exception as e:
                            print(f"[Socket Emit Error] {e}")

        except Exception as e:
            print(f"[Monitoring Error] {e}")

        time.sleep(5)

def start_monitoring_in_thread(socketio):
    print("[Startup] Initializing anomaly prediction monitoring...")
    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_TXT_FILE), exist_ok=True)
    
    # Initialize with a startup message in the output file
    startup_msg = {
        "type": "system_event",
        "event": "startup",
        "message": "Anomaly prediction monitoring started",
        "timestamp": datetime.utcnow().isoformat()
    }
    write_predictive_output(startup_msg)
    
    thread = threading.Thread(target=monitor_logs, args=(socketio,))
    thread.daemon = True
    thread.start()
    print("[Startup] Anomaly prediction monitoring thread started!")
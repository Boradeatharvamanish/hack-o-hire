import os
import json
import time
import threading
from datetime import datetime
from sklearn.ensemble import IsolationForest
from collections import defaultdict
import numpy as np

LOG_DIR = r"C:\Users\Administrator\OneDrive\Desktop\demo\logs"
OUTPUT_TXT_FILE = r"C:\Users\Administrator\OneDrive\Desktop\demo\utils\predictive_analysis_result.txt"

last_seen = {}
api_error_history = defaultdict(lambda: {"total": 0, "errors": 0})

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

def trigger_alert(api, env, rate):
    print(f"[ALERT] 🚨 High error rate detected! API: '{api}' | Environment: '{env}' | Error Rate: {rate:.2f}")
    # Extend this to send alerts via email, Slack, etc.

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

    # Check historical error rate
    err_rate = get_error_rate(api_type, environment)
    if err_rate > 0.25:
        impact_score += 2
        reasons.append(f"High historical error rate: {err_rate:.2f}")

    # ----------- Alert condition -----------
    if err_rate > 0.3:
        trigger_alert(api_type, environment, err_rate)
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
        "historical_error_rate": err_rate
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
        with open(OUTPUT_TXT_FILE, 'a') as f:
            json_str = json.dumps(data, indent=2, default=convert_json_safe)
            f.write(json_str)
            f.write("\n\n")
    except Exception as e:
        print(f"[Write Error] Failed to write output: {e}")

# ---------------- Real-time Socket Monitor ------------------

def monitor_logs(socketio):
    seen_anomalies = set()

    print("[Monitor] Real-time log socket monitoring started...")
    while True:
        try:
            if os.path.exists(OUTPUT_TXT_FILE):
                with open(OUTPUT_TXT_FILE, 'r') as f:
                    raw_logs = f.read().strip().split("\n\n")

                for raw in raw_logs:
                    if raw.strip():
                        try:
                            log = json.loads(raw)
                            if log.get("historical_error_rate", 0) > 0.5:
                                anomaly_id = f"{log['api']}_{log['timestamp']}"
                                if anomaly_id not in seen_anomalies:
                                    seen_anomalies.add(anomaly_id)
                                    socketio.emit('new_anomaly', {
                                        "api": log["api"],
                                        "env": log.get("environment", "unknown"),
                                        "error_rate": log["historical_error_rate"],
                                        "timestamp": log["timestamp"]
                                    })
                        except Exception as e:
                            print(f"[Socket Emit Error] {e}")

        except Exception as e:
            print(f"[Monitoring Error] {e}")

        time.sleep(5)
def start_monitoring_in_thread(socketio):
    thread = threading.Thread(target=monitor_logs, args=(socketio,))
    thread.daemon = True
    thread.start()


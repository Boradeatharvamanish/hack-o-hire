import uuid
import random
import time
from datetime import datetime, timedelta
from faker import Faker
from utils.api_state import is_api_failing, set_api_failure

fake = Faker()

def generate_log(api_name, req_info=None, previous_api=None):
    if req_info is None:
        req_info = {}

    correlation_id = req_info.get("correlation_id") or str(uuid.uuid4())
    session_id = req_info.get("session_id") or str(uuid.uuid4())
    user_id = req_info.get("user_id") or str(uuid.uuid4())

    # Simulated request and response metadata
    request_id = f"req-{uuid.uuid4().hex[:16]}"
    method = random.choice(["GET", "POST"])
    path = f"/{api_name}"
    user_agent = fake.user_agent()
    source_ip = fake.ipv4()

    response_time_ms = round(random.uniform(100, 500), 2)

    # Simulate API being in a degraded state
    if is_api_failing(api_name):
        is_anomalous = True
        status_code = random.choice([500, 503, 504])
        success = False
        error_info = f"API returned error code {status_code}. Ongoing issue due to prior failure."
    else:
        # Random chance to simulate a new failure
        if random.random() < 0.1:  # 10% chance
            is_anomalous = True
            status_code = random.choice([500, 503, 504])
            success = False
            error_info = f"API returned error code {status_code}. Possible spike in failures."
            set_api_failure(api_name, duration_secs=90)
        else:
            is_anomalous = False
            status_code = 200
            success = True
            error_info = None

    # Log structure
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        f"{api_name}_service": {
            "type": random.choice(["rest", "graphql"]),
            "environment": random.choice(["on-prem", "cloud", "multi-cloud"]),
            "region": random.choice(["us-east", "us-west", "eu-west", "asia-south"]),
            "instance_id": f"{api_name}-instance-{random.randint(1, 10)}"
        },
        "request": {
            "id": request_id,
            "method": method,
            "path": path,
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": user_agent,
                "X-Request-ID": request_id
            },
            "body": req_info.get("body", {}),
            "client_id": f"client-{uuid.uuid4().hex[:8]}",
            "client_type": random.choice(["internal-service", "browser", "mobile-app"]),
            "source_ip": source_ip
        },
        "response": {
            "status_code": status_code,
            "body": {
                "message": f"{api_name} request {'processed successfully' if success else 'failed'}",
                "session_token": None
            },
            "time_ms": response_time_ms
        },
        "operation": {
            "type": api_name,
            "success": success,
            "user_id": user_id,
            "tenant_id": f"tenant-{random.randint(1, 100)}"
        },
        "security": {
            "mfa_used": random.choice([True, False]),
            "ip_reputation": random.choice(["trusted", "unknown", "suspicious"]),
            "rate_limit": {
                "limit": 100,
                "remaining": random.randint(0, 100),
                "reset": int(time.time()) + 3600
            }
        },
        "tracing": {
            "correlation_id": correlation_id,
            "request_id": request_id,
            "previous_api": previous_api,
            "session_id": session_id
        },
        "is_anomalous": is_anomalous,
        "error_info": error_info
    }

    return log, correlation_id, session_id, user_id


def save_log(log, api_name):
    import os, json
    folder = "logs"
    os.makedirs(folder, exist_ok=True)
    with open(f"{folder}/{api_name}_logs.json", "a") as f:
        f.write(json.dumps(log) + "\n")

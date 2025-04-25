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

    # Hardcode server_id based on API type
    if api_name in ["auth", "make_payment", "catalog"]:
        server_id = "server_1"
    else:
        server_id = "server_2"
    
    # If server_id was passed in req_info, use that instead (for consistency in the session)
    if req_info.get("server_id"):
        server_id = req_info.get("server_id")
        
    instance_id = req_info.get("instance_id") or f"instance_{random.randint(1, 10)}"

    request_id = f"req-{uuid.uuid4().hex[:16]}"
    method = random.choice(["GET", "POST"])
    path = f"/{api_name}"
    user_agent = fake.user_agent()
    source_ip = fake.ipv4()
    response_time_ms = round(random.uniform(100, 500), 2)

    if is_api_failing(api_name):
        is_anomalous = True
        status_code = random.choice([500, 503, 504])
        success = False
        error_info = f"API returned error code {status_code}. Ongoing issue due to prior failure."
    else:
        if random.random() < 0.1:
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
    
    # Determine environment based on API type (for testing purposes)
    if api_name in ["auth", "make_payment"]:
        environment = "on-prem"
    else:
        environment = random.choice(["cloud", "multi-cloud"])
            
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "meta": {
            "environment": environment,
            "region": random.choice(["us-east", "us-west", "eu-west", "asia-south"]),
            "retry_count": random.randint(0, 3)
        },
        f"{api_name}_service": {
            "type": random.choice(["rest", "graphql"]),
            "environment": environment,
            "region": random.choice(["us-east", "us-west", "eu-west", "asia-south"]),
            "instance_id": instance_id,
            "server_id": server_id
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
            "session_id": session_id,
            "server_id": server_id,  # Add server_id to tracing for anomaly detection
            "previous_server_id": get_previous_server_id(previous_api),
            "session_failures": random.randint(0, 2)
        },
        "server_context": {
            "server_id": server_id,
            "instance_id": instance_id
        },
        "is_anomalous": is_anomalous,
        "error_info": error_info
    }

    return log, correlation_id, session_id, user_id

def get_previous_server_id(previous_api):
    """Helper function to determine previous server ID"""
    if not previous_api:
        return None
    
    if previous_api in ["auth", "make_payment", "catalog"]:
        return "server_1"
    else:
        return "server_2"

def save_log(log, api_name):
    import os, json
    folder = "logs"
    os.makedirs(folder, exist_ok=True)
    with open(f"{folder}/{api_name}_logs.json", "a") as f:
        f.write(json.dumps(log) + "\n")
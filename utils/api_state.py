from datetime import datetime, timedelta

# Global in-memory API failure map
api_failure_state = {}

def set_api_failure(api_name, duration_secs=60):
    api_failure_state[api_name] = {
        "until": datetime.utcnow() + timedelta(seconds=duration_secs)
    }

def is_api_failing(api_name):
    info = api_failure_state.get(api_name)
    if info and info["until"] > datetime.utcnow():
        return True
    return False

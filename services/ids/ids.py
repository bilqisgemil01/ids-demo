import os, time, re
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import defaultdict, deque

# Step 2: 
# - Tail-follow the Mosquitto log file
# - Parse CONNECT / DISCONNECT lines
# + 
# - Detect connection churn as "many short sessions" in a sliding window
# - Alert grouped by both source IP and client_id

# log timestamp format: 
# YYYY-MM-DDTHH:MM:SS+0000: <message...>
TS_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

CONNECT_RE = re.compile(
    r"^New client connected from (?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+) as (?P<client>\S+)\s"
)

DISCONNECT_RE = re.compile(
    r"^Client (?P<client>\S+) \[(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)\] disconnected\."
)

@dataclass(frozen=True)
class Event:
    ts: datetime
    typ: str    # "CONNECT" / "DISCONNECT"
    client_id: str
    ip: str
    port: int
    raw: str

def parse_timestamp(prefix: str) -> datetime:
    return datetime.strptime(prefix, TS_FORMAT)

def parse_line(line: str) -> Event | None:
    # Convert a Mosquitto log line into an Event (CONNECT/DISCONNECT) if it matches.
    # Otherwise return None.
    try: 
        ts_part, msg = line.split(": ", 1)
    except ValueError:
        return None
    
    # Some lines are startup info etc => ignore them.
    try: 
        ts = parse_timestamp(ts_part)
    except Exception:
        return None
    
    m = CONNECT_RE.match(msg)
    if m:
        return Event(
            ts = ts, 
            typ = "CONNECT", 
            client_id=m.group("client"), 
            ip=m.group("ip"), 
            port=int(m.group("port")), 
            raw=line
        )
    
    m = DISCONNECT_RE.match(msg)
    if m: 
        return Event(
            ts=ts, 
            typ="DISCONNECT", 
            client_id=m.group("client"), 
            ip=m.group("ip"), 
            port=int(m.group("port")), 
            raw=line
        )
    
    return None

def tail_file(path: str):
    # Wait until file exists
    while not os.path.exists(path):
        print(f"[ids] waiting for log file: {path}")
        time.sleep(0.5)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")

def main():
    log_path = os.getenv("LOG_PATH", "/evidence/mosquitto.log")

    # Churn rule params
    churn_window_sec = int(os.getenv("CHURN_WINDOW_SEC", "5"))
    churn_threshold = int(os.getenv("CHURN_THRESHOLD", "10"))
    short_session_sec = float(os.getenv("SHORT_SESSION_SEC", "2"))
    cooldown_sec = int(os.getenv("COOLDOWN_SEC", "10"))

    print(f"[ids] Step 2: churn detection (log tail) from {log_path}")
    print(f"[ids] churn_window_sec={churn_window_sec} churn_threshold={churn_threshold} short_session_sec={short_session_sec}")
    
    # Session starts keyed by unique socker identity (client_id, ip, port)
    session_start: dict[tuple[str, str, int], float] = {}

    # Sliding window: short session timestamps grouped by IP and client
    short_by_ip: dict[str, deque[float]] = defaultdict(deque)
    short_by_client: dict[str, deque[float]] = defaultdict(deque)

    last_alert: dict[tuple[str, str], float] = {}

    for line in tail_file(log_path):
        ev = parse_line(line)
        if ev is None:
            continue

        # Structured output (easy to validate)
        # Example:
        # CONNECT ts=2026-03-14T12:06:40+00:00 ip=172.18.0.7 port=53328 client=attacker1
        print(
            f"{ev.typ} ts={ev.ts.astimezone(timezone.utc).isoformat()} "
            f"ip={ev.ip} port={ev.port} client={ev.client_id}"
        )

        ts_sec = ev.ts.timestamp()

        key = (ev.client_id, ev.ip, ev.port)

        if ev.typ == "CONNECT":
            session_start[key] = ts_sec
            continue

        # DISCONNECT
        start_sec = session_start.pop(key, None)
        if start_sec is None:
            # Didn't observe the CONNECT (maybe IDS started mid-stream) => ignore
            continue

        duration = ts_sec - start_sec

        # Only count short-lived sessions as churn evidence
        if duration > short_session_sec:
            continue

        # Record event in both groupings
        dq_ip = short_by_ip[ev.ip]
        dq_client = short_by_client[ev.client_id]
        dq_ip.append(ts_sec)
        dq_client.append(ts_sec)

        # Evict old entries outside window
        cutoff = ts_sec - churn_window_sec
        while dq_ip and dq_ip[0] < cutoff:
            dq_ip.popleft()
        while dq_client and dq_client[0] < cutoff:
            dq_client.popleft()

        # Alert grouped by IP
        ip_alert_key = ("CHURN_IP", ev.ip)
        if len(dq_ip) >= churn_threshold and (ts_sec - last_alert.get(ip_alert_key, 0) >= cooldown_sec):
            last_alert[ip_alert_key] = ts_sec
            print(
                f"ALERT_CHURN_IP ip={ev.ip} short_sessions_in_{churn_window_sec}s={len(dq_ip)} "
                f"threshold={churn_threshold} last_duration={duration:.3f}s"
            )

        client_alert_key = ("CHURN_CLIENT", ev.client_id)
        if len(dq_client) >= churn_threshold and (ts_sec - last_alert.get(client_alert_key, 0) >= cooldown_sec):
            last_alert[client_alert_key] = ts_sec
            print(
                f"ALERT_CHURN_CLIENT client={ev.client_id} short_sessions_in_{churn_window_sec}s={len(dq_client)} "
                f"threshold={churn_threshold} last_duration={duration:.3f}s"
            )

if __name__ == "__main__":
    main()
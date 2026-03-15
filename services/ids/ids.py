import os, time, re, threading, json, uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import defaultdict, deque

import paho.mqtt.client as mqtt

# Step 4: 
# - Tail-follow the Mosquitto log file
# - Parse CONNECT / DISCONNECT lines
# + 
# - Detect connection churn as "many short sessions" in a sliding window
# - Alert grouped by both source IP and client_id
# + 
# - Add MQTT subscription channel (paho-mqtt) to observe message-rate floods directly
# - Detect message flood + alert
# + 
# - Emit JSON alert files to ALERT_DIR (atomic write)

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

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def canonical_ts_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def safe_token(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)

def emit_alert(alert_dir: str, payload: dict) -> str:
    """
    Write alert as JSON with atomic replace:
    - write temp file
    - os.replace to final name
    Returns the final path.
    """
    os.makedirs(alert_dir, exist_ok=True)

    # Add common fields if not present
    payload = dict(payload)
    payload.setdefault("schema_version", "1.0")
    payload.setdefault("id", str(uuid.uuid4()))
    payload.setdefault("ts", utc_now_iso())

    rule_id = payload.get("rule_id", "UNKNOWN")
    group = payload.get("group", "NA")
    ts = canonical_ts_for_filename()
    rid = payload["id"].split("-")[0]   # short unique token

    filename = f"alert-{ts}-{safe_token(rule_id)}-{safe_token(str(group))}-{rid}.json"
    final_path = os.path.join(alert_dir, filename)
    tmp_path = final_path + ".tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    os.replace(tmp_path, final_path)
    return final_path

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

class MsgCounter:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.last_print_total = 0
        self.last_print_time = time.time()

    def inc_and_get(self, n: int = 1) -> int:
        with self.lock:
            self.total += n
            return self.total

    def maybe_print(self, every_n: int = 25, min_interval_sec: float = 1.0):
        now = time.time()
        with self.lock:
            delta = self.total - self.last_print_total
            if delta >= every_n:
                if delta > 0:
                    print(f"[mqtt] received +{delta} messages (total={self.total})")
                    self.last_print_total = self.total
                    self.last_print_time = now 

def start_mqtt_listener(counter: MsgCounter, alert_dir: str):
    host = os.getenv("MQTT_HOST", "mosquitto")
    port = int(os.getenv("MQTT_PORT", "1883"))
    topic = os.getenv("MQTT_TOPIC", "attack/msgflood")
    client_id = os.getenv("MQTT_CLIENT_ID", "ids1")

    msg_window_sec = int(os.getenv("MSG_WINDOW_SEC", "5"))
    msg_threshold = int(os.getenv("MSG_THRESHOLD", "100"))
    cooldown_sec = int(os.getenv("COOLDOWN_SEC", "10"))

    msg_times = deque()     # timestamps of received messages
    recent_payloads = deque(maxlen=5)
    last_msg_alert = 0.0    # for cooldown

    # Callback API v2 signatures (paho-mqtt 2.x)
    def on_connect(client, userdata, flags, reason_code, properties):
        # reason_code == 0 means success 
        print(f"[mqtt] connected reason_code={reason_code} host={host}:{port} client_id={client_id}")
        result, mid = client.subscribe(topic, qos=0)
        print(f"[mqtt] subscribe requested topic={topic} result={result} mid={mid}")

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        print(f"[mqtt] subscribed mid={mid} reason_codes={list(reason_codes)}")

    def on_message(client, userdata, msg):
        new_total = counter.inc_and_get(1)

        recent_payloads.append(msg.payload[:50])

        if new_total <= 5:
            print(f"[mqtt] msg#{new_total} topic={msg.topic} payload_preview={msg.payload[:50]!r}")

        nonlocal last_msg_alert

        now = time.time()
        msg_times.append(now)
        cutoff = now - msg_window_sec
        while msg_times and msg_times[0] < cutoff:
            msg_times.popleft()

        if len(msg_times) >= msg_threshold and (now - last_msg_alert) >= cooldown_sec:
            last_msg_alert = now
            print(
                f"ALERT_MSG_FLOOD topic={msg.topic} "
                f"msgs_in_{msg_window_sec}s={len(msg_times)} threshold={msg_threshold}"
            )

            payload = {
                "rule_id": "MSG_FLOOD",
                "severity": "HIGH",
                "source": "mqtt",
                "group": msg.topic,
                "stats": {
                    "window_sec": msg_window_sec,
                    "count_in_window": len(msg_times),
                    "threshold": msg_threshold,
                },
                "evidence": {
                    "recent_payload_previews": [p.decode("utf-8", errors="replace") for p in list(recent_payloads)],
                },
            }
            path = emit_alert(alert_dir, payload)
            print(f"[ids] wrote alert: {path}")
        
        counter.maybe_print(every_n=25, min_interval_sec=1.0)

    def on_disconnect(client, userdata, reason_code, properties):
        print(f"[mqtt] disconnected reason_code={reason_code}")

    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_subscribe = on_subscribe
    mqtt_client.on_message = on_message
    mqtt_client.on_disconnect = on_disconnect

    while True:
        try:
            mqtt_client.connect(host, port, keepalive=60)
            mqtt_client.loop_forever()
        except Exception as e:
            print(f"[mqtt] error: {e} (retrying in 2s)")
            time.sleep(2)

def main():
    log_path = os.getenv("LOG_PATH", "/evidence/mosquitto.log")
    alert_dir = os.getenv("ALERT_DIR", "/alerts")

    # Churn rule params
    churn_window_sec = int(os.getenv("CHURN_WINDOW_SEC", "5"))
    churn_threshold = int(os.getenv("CHURN_THRESHOLD", "10"))
    short_session_sec = float(os.getenv("SHORT_SESSION_SEC", "2"))
    cooldown_sec = int(os.getenv("COOLDOWN_SEC", "10"))

    print(f"[ids] Step 4: JSON alerts (unsigned)")
    print(f"[ids] log={log_path}")
    print(f"[ids] alert_dir={alert_dir}")
    print(f"[ids] churn_window_sec={churn_window_sec} churn_threshold={churn_threshold} short_session_sec={short_session_sec}")

    # Start MQTT listener in background
    msg_counter = MsgCounter()
    t = threading.Thread(target=start_mqtt_listener, args=(msg_counter,alert_dir),daemon=True)
    t.start()
    
    session_start: dict[tuple[str, str, int], float] = {}
    short_by_ip: dict[str, deque[float]] = defaultdict(deque)
    short_by_client: dict[str, deque[float]] = defaultdict(deque)
    last_alert: dict[tuple[str, str], float] = {}

    recent_lines_by_ip: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=6))
    recent_lines_by_client: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=6))

    for line in tail_file(log_path):
        ev = parse_line(line)
        if ev is None:
            continue

        recent_lines_by_ip[ev.ip].append(ev.raw)
        recent_lines_by_client[ev.client_id].append(ev.raw)

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
            continue

        duration = ts_sec - start_sec

        if duration > short_session_sec:
            continue

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

            payload = {
                "rule_id": "CHURN_IP",
                "severity": "HIGH",
                "source": "mosquitto_log",
                "group": ev.ip,
                "stats": {
                    "window_sec": churn_window_sec,
                    "count_in_window": len(dq_ip),
                    "threshold": churn_threshold,
                    "short_session_sec": short_session_sec,
                    "last_duration_sec": round(duration, 6),
                },
                "evidence": {
                    "recent_log_lines": list(recent_lines_by_ip[ev.ip]),
                },
            }
            path = emit_alert(alert_dir, payload)
            print(f"[ids] wrote alert: {path}")

        client_alert_key = ("CHURN_CLIENT", ev.client_id)
        if len(dq_client) >= churn_threshold and (ts_sec - last_alert.get(client_alert_key, 0) >= cooldown_sec):
            last_alert[client_alert_key] = ts_sec
            print(
                f"ALERT_CHURN_CLIENT client={ev.client_id} short_sessions_in_{churn_window_sec}s={len(dq_client)} "
                f"threshold={churn_threshold} last_duration={duration:.3f}s"
            )

            payload = {
                "rule_id": "CHURN_CLIENT",
                "severity": "MEDIUM",
                "source": "mosquitto_log",
                "group": ev.client_id,
                "stats": {
                    "window_sec": churn_window_sec,
                    "count_in_window": len(dq_client),
                    "threshold": churn_threshold,
                    "short_session_sec": short_session_sec,
                    "last_duration_sec": round(duration, 6),
                },
                "evidence": {
                    "recent_log_lines": list(recent_lines_by_client[ev.client_id]),
                },
            }
            path = emit_alert(alert_dir, payload)
            print(f"[ids] wrote alert: {path}")

if __name__ == "__main__":
    main()
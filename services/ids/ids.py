import os, time, re
from dataclasses import dataclass
from datetime import datetime, timezone

# Step 1: 
# - Tail-follow the Mosquitto log file
# - Parse CONNECT / DISCONNECT lines
# - Print structured events

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
    typ: str
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
    print(f"[ids] Step 1: tail + parse CONNECT/DISCONNECT from {log_path}")

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

if __name__ == "__main__":
    main()
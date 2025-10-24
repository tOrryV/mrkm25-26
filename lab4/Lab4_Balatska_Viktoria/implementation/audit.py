from datetime import datetime

def log_event(kind, kid, detail):
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    print(f"[audit] {ts} | {kind} | KID={kid} | {detail}")

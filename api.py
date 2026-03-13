"""
SentinelMind - FastAPI Backend
Serves audit log data to the React dashboard
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import json
from config import Config

app = FastAPI(title="SentinelMind API", version="1.0.0")
config = Config()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/")
def root():
    return {"status": "SentinelMind API running", "version": "1.0.0"}


@app.get("/api/events")
def get_events(limit: int = 50):
    """Returns recent threat events from audit log."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    events = []
    for row in rows:
        e = dict(row)
        e["reasoning_steps"] = json.loads(e.get("reasoning_steps") or "[]")
        events.append(e)
    return {"events": events, "count": len(events)}


@app.get("/api/stats")
def get_stats():
    """Returns summary statistics for dashboard."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM audit_log WHERE severity='CRITICAL'").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM audit_log WHERE severity='HIGH'").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action_taken='block_ip'").fetchone()[0]
    conn.close()
    return {
        "total_threats": total,
        "critical": critical,
        "high": high,
        "ips_blocked": blocked,
        "auto_resolved": blocked,
    }


@app.get("/api/events/{event_id}")
def get_event(event_id: str):
    """Returns a single event with full reasoning trace."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM audit_log WHERE event_id=?", (event_id,)
    ).fetchone()
    conn.close()
    if not row:
        return {"error": "Event not found"}
    e = dict(row)
    e["reasoning_steps"] = json.loads(e.get("reasoning_steps") or "[]")
    return e
"""
SentinelMind - Log & Network Monitor
Streams system log events in real time
"""

import asyncio
import random
import time
import logging
from datetime import datetime

logger = logging.getLogger("Monitor")

# Simulated event templates for demo purposes
SAMPLE_EVENTS = [
    {
        "type": "failed_login",
        "source": "192.168.1.105",
        "user": "admin",
        "count": 47,
        "timestamp": None,
        "raw": "Failed password for admin from 192.168.1.105 port 22 ssh2"
    },
    {
        "type": "port_scan",
        "source": "10.0.0.55",
        "ports_scanned": 1024,
        "timestamp": None,
        "raw": "Nmap scan detected: 1024 ports probed from 10.0.0.55"
    },
    {
        "type": "suspicious_process",
        "source": "localhost",
        "process": "nc -lvp 4444",
        "pid": 3821,
        "timestamp": None,
        "raw": "Suspicious process started: nc -lvp 4444 by user www-data"
    },
    {
        "type": "data_exfiltration",
        "source": "172.16.0.10",
        "bytes_sent": 524288000,
        "destination": "198.51.100.42",
        "timestamp": None,
        "raw": "Large outbound transfer: 500MB to unknown IP 198.51.100.42"
    },
    {
        "type": "privilege_escalation",
        "source": "localhost",
        "user": "www-data",
        "command": "sudo su -",
        "timestamp": None,
        "raw": "Privilege escalation attempt: www-data ran sudo su -"
    },
    {
        "type": "normal_traffic",
        "source": "192.168.1.1",
        "timestamp": None,
        "raw": "Normal HTTP request from 192.168.1.1"
    },
]


class LogMonitor:
    """
    Monitors log files and network traffic.
    In production: tails real log files using watchdog.
    In demo: streams simulated events.
    """

    def __init__(self, config):
        self.config = config
        self.running = True
        logger.info(f"LogMonitor initialized. Watching: {config.LOG_FILE_PATH}")

    async def stream_events(self):
        """
        Async generator that yields log events.
        Simulates real-time monitoring for demo.
        """
        logger.info("📡 Starting event stream...")
        event_count = 0

        while self.running:
            await asyncio.sleep(self.config.MONITOR_INTERVAL)

            # Pick a random event (weighted: more normal than malicious)
            weights = [15, 10, 8, 5, 7, 55]  # last one is normal_traffic
            event = random.choices(SAMPLE_EVENTS, weights=weights, k=1)[0].copy()
            event["timestamp"] = datetime.now().isoformat()
            event["event_id"] = f"EVT-{event_count:05d}"
            event_count += 1

            # Skip normal traffic (no anomaly to detect)
            if event["type"] == "normal_traffic":
                logger.debug(f"[{event['event_id']}] Normal traffic — skipping")
                continue

            logger.info(f"[{event['event_id']}] New event: {event['type']} from {event['source']}")
            yield event

    def stop(self):
        self.running = False
        logger.info("Monitor stopped.")
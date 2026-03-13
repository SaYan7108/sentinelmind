"""
SentinelMind - Autonomous Responder
Executes response actions based on threat assessment
"""

import logging
import sqlite3
import json
from datetime import datetime

logger = logging.getLogger("Responder")


class AutonomousResponder:
    """
    Executes autonomous response actions and logs everything
    to an audit trail in SQLite.
    """

    def __init__(self, config):
        self.config = config
        self._init_db()
        logger.info("AutonomousResponder initialized.")

    def _init_db(self):
        """Creates the audit log table if it doesn't exist."""
        conn = sqlite3.connect(self.config.DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                event_type TEXT,
                source TEXT,
                severity TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                explanation TEXT,
                action_taken TEXT,
                action_detail TEXT,
                confidence REAL,
                reasoning_steps TEXT,
                timestamp TEXT,
                created_at TEXT
            )
        """)
        conn.commit()
        conn.close()
        logger.info(f"Audit log DB initialized at {self.config.DB_PATH}")

    async def respond(self, assessment: dict) -> dict:
        """
        Executes the recommended action and logs the result.
        Returns a dict with action taken and details.
        """
        action = assessment.get("recommended_action", "alert_only")
        source = assessment.get("source", "unknown")
        severity = assessment.get("severity", "HIGH")

        result = {
            "action": action,
            "detail": "",
            "success": False
        }

        # Execute action
        if action == "block_ip" and self.config.AUTO_BLOCK_ENABLED:
            result = self._block_ip(source)

        elif action == "kill_process" and self.config.AUTO_KILL_PROCESS_ENABLED:
            pid = assessment.get("pid")
            result = self._kill_process(pid)

        elif action == "isolate_endpoint":
            result = self._isolate_endpoint(source)

        elif action == "alert_only":
            result = self._send_alert(assessment)

        else:
            result = {"action": "no_action", "detail": "Threat below auto-response threshold", "success": True}

        # Log to audit trail
        self._log_to_db(assessment, result)

        logger.info(f"📋 Audit logged | Action: {result['action']} | Success: {result['success']}")
        return result

    def _block_ip(self, ip: str) -> dict:
        """Blocks an IP address via iptables (simulated in demo)."""
        # In production: os.system(f"iptables -A INPUT -s {ip} -j DROP")
        logger.warning(f"🚫 [SIMULATED] Blocking IP: {ip}")
        return {
            "action": "block_ip",
            "detail": f"IP {ip} blocked via iptables firewall rule",
            "success": True
        }

    def _kill_process(self, pid) -> dict:
        """Kills a suspicious process (simulated in demo)."""
        # In production: os.kill(pid, signal.SIGTERM)
        logger.warning(f"💀 [SIMULATED] Killing process PID: {pid}")
        return {
            "action": "kill_process",
            "detail": f"Process PID {pid} terminated",
            "success": True
        }

    def _isolate_endpoint(self, host: str) -> dict:
        """Isolates an endpoint from the network (simulated)."""
        # In production: trigger network isolation via EDR API
        logger.warning(f"🔒 [SIMULATED] Isolating endpoint: {host}")
        return {
            "action": "isolate_endpoint",
            "detail": f"Host {host} isolated from network",
            "success": True
        }

    def _send_alert(self, assessment: dict) -> dict:
        """Sends an alert to the SOC team (simulated)."""
        # In production: send email/Slack/PagerDuty alert
        logger.info(f"📧 [SIMULATED] Alert sent to SOC: {assessment.get('event_type')} — {assessment.get('severity')}")
        return {
            "action": "alert_only",
            "detail": f"SOC team alerted via email ({self.config.ALERT_EMAIL})",
            "success": True
        }

    def _log_to_db(self, assessment: dict, result: dict):
        """Saves full audit record to SQLite."""
        conn = sqlite3.connect(self.config.DB_PATH)
        conn.execute("""
            INSERT INTO audit_log (
                event_id, event_type, source, severity,
                mitre_tactic, mitre_technique, explanation,
                action_taken, action_detail, confidence,
                reasoning_steps, timestamp, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            assessment.get("event_id"),
            assessment.get("event_type"),
            assessment.get("source"),
            assessment.get("severity"),
            assessment.get("mitre_tactic"),
            assessment.get("mitre_technique"),
            assessment.get("explanation"),
            result.get("action"),
            result.get("detail"),
            assessment.get("confidence"),
            json.dumps(assessment.get("reasoning_steps", [])),
            assessment.get("timestamp"),
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
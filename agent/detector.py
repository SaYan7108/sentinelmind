"""
SentinelMind - Anomaly Detector
Scores events and flags genuine threats
"""

import logging

logger = logging.getLogger("Detector")

# Threat scoring rules per event type
THREAT_SCORES = {
    "failed_login": lambda e: min(0.4 + (e.get("count", 1) / 100), 0.99),
    "port_scan": lambda e: 0.82,
    "suspicious_process": lambda e: 0.91,
    "data_exfiltration": lambda e: 0.97,
    "privilege_escalation": lambda e: 0.95,
    "normal_traffic": lambda e: 0.0,
}


class AnomalyDetector:
    """
    Rule-based + heuristic anomaly detection engine.
    Assigns a threat score [0.0 - 1.0] to each event.
    """

    def __init__(self, config):
        self.config = config
        self.threshold = config.ANOMALY_THRESHOLD
        logger.info(f"AnomalyDetector initialized. Threshold: {self.threshold}")

    def analyze(self, event: dict) -> dict | None:
        """
        Analyzes an event and returns enriched anomaly dict,
        or None if the event is below the threat threshold.
        """
        event_type = event.get("type", "unknown")
        scorer = THREAT_SCORES.get(event_type, lambda e: 0.5)
        score = scorer(event)

        logger.debug(f"Event '{event_type}' scored: {score:.2f}")

        if score < self.threshold:
            return None

        severity = self._score_to_severity(score)

        anomaly = {
            **event,
            "threat_score": round(score, 2),
            "severity": severity,
        }

        logger.warning(
            f"Anomaly flagged | Type: {event_type} | Score: {score:.2f} | Severity: {severity}"
        )
        return anomaly

    def _score_to_severity(self, score: float) -> str:
        if score >= self.config.CRITICAL_SEVERITY_SCORE:
            return "CRITICAL"
        elif score >= self.config.HIGH_SEVERITY_SCORE:
            return "HIGH"
        elif score >= self.config.ANOMALY_THRESHOLD:
            return "MEDIUM"
        else:
            return "LOW"
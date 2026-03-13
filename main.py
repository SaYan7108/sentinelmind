"""
SentinelMind - Autonomous Cyber Threat Detection & Response
Main entry point
"""

import asyncio
import logging
from agent.monitor import LogMonitor
from agent.detector import AnomalyDetector
from agent.reasoner import ThreatReasoner
from agent.responder import AutonomousResponder
from config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SentinelMind")


async def run_sentinel():
    """Main pipeline: Monitor → Detect → Reason → Respond"""
    logger.info("🛡️  SentinelMind starting up...")

    config = Config()
    monitor = LogMonitor(config)
    detector = AnomalyDetector(config)
    reasoner = ThreatReasoner(config)
    responder = AutonomousResponder(config)

    logger.info("✅ All modules initialized. Watching for threats...\n")

    async for event in monitor.stream_events():
        # Step 1: Detect anomaly
        anomaly = detector.analyze(event)
        if not anomaly:
            continue

        logger.warning(f"⚠️  Anomaly detected: {anomaly['type']} from {anomaly['source']}")

        # Step 2: LLM reasoning
        threat_assessment = await reasoner.assess(anomaly)
        logger.info(f"🧠 Reasoning: {threat_assessment['explanation']}")
        logger.info(f"   Threat Level: {threat_assessment['severity']} | Tactic: {threat_assessment['mitre_tactic']}")

        # Step 3: Autonomous response
        if threat_assessment["severity"] in ["HIGH", "CRITICAL"]:
            action = await responder.respond(threat_assessment)
            logger.info(f"🚨 Action taken: {action['action']} — {action['detail']}")
        else:
            logger.info("ℹ️  Low severity — logged for analyst review.")


if __name__ == "__main__":
    asyncio.run(run_sentinel())
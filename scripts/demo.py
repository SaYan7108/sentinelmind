"""
SentinelMind - Demo Script
Simulates a cyber attack scenario end-to-end without needing real logs
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.detector import AnomalyDetector
from agent.reasoner import ThreatReasoner
from agent.responder import AutonomousResponder
from config import Config


DEMO_EVENTS = [
    {
        "event_id": "EVT-00001",
        "type": "failed_login",
        "source": "192.168.1.105",
        "user": "admin",
        "count": 47,
        "timestamp": "2024-01-15T14:23:01",
        "raw": "Failed password for admin from 192.168.1.105 port 22 ssh2"
    },
    {
        "event_id": "EVT-00002",
        "type": "port_scan",
        "source": "10.0.0.55",
        "ports_scanned": 1024,
        "timestamp": "2024-01-15T14:25:30",
        "raw": "Nmap scan detected: 1024 ports probed from 10.0.0.55"
    },
    {
        "event_id": "EVT-00003",
        "type": "data_exfiltration",
        "source": "172.16.0.10",
        "bytes_sent": 524288000,
        "destination": "198.51.100.42",
        "timestamp": "2024-01-15T14:30:00",
        "raw": "Large outbound transfer: 500MB to unknown IP 198.51.100.42"
    },
]


async def run_demo():
    print("\n" + "="*60)
    print("  🛡️  SentinelMind - DEMO MODE")
    print("="*60)
    print("Simulating a multi-stage cyber attack...\n")

    config = Config()
    detector = AnomalyDetector(config)
    reasoner = ThreatReasoner(config)
    responder = AutonomousResponder(config)

    for event in DEMO_EVENTS:
        print(f"\n{'─'*50}")
        print(f"📥 EVENT: {event['type'].upper()} from {event['source']}")
        print(f"   Raw: {event['raw']}")

        # Detect
        anomaly = detector.analyze(event)
        if not anomaly:
            print("   ✅ No anomaly detected.")
            continue
        print(f"   ⚠️  Anomaly Score: {anomaly['threat_score']} | Severity: {anomaly['severity']}")

        # Reason
        print("   🧠 Sending to LLM for reasoning...")
        assessment = await reasoner.assess(anomaly)
        print(f"   📌 Tactic: {assessment['mitre_tactic']} | Technique: {assessment['mitre_technique']}")
        print(f"   💬 Explanation: {assessment['explanation']}")
        print(f"   🎯 Recommended Action: {assessment['recommended_action']}")

        if assessment.get("reasoning_steps"):
            print("   🔍 Reasoning Steps:")
            for step in assessment["reasoning_steps"]:
                print(f"      → {step}")

        # Respond
        result = await responder.respond(assessment)
        print(f"   🚨 ACTION TAKEN: {result['action']} — {result['detail']}")

        await asyncio.sleep(1)

    print(f"\n{'='*60}")
    print("✅ Demo complete! Check sentinelmind.db for full audit log.")
    print("   Run `python api.py` to start the API server.")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(run_demo())
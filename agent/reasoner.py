"""
SentinelMind - LLM Threat Reasoner
Uses GPT-4o to reason about threats using chain-of-thought
and maps them to MITRE ATT&CK framework
"""

import json
import logging
from openai import AsyncOpenAI
from agent.mitre_mapper import get_mitre_info

logger = logging.getLogger("Reasoner")


SYSTEM_PROMPT = """
You are SentinelMind, an expert AI cybersecurity analyst.
You will be given a suspicious system event. Your job is to:
1. Analyze the threat carefully using chain-of-thought reasoning
2. Assign a severity level: LOW, MEDIUM, HIGH, or CRITICAL
3. Map it to a MITRE ATT&CK tactic
4. Recommend an immediate autonomous response action
5. Write a short plain-English explanation for the audit log

Always respond in valid JSON with this exact structure:
{
  "severity": "HIGH",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1110 - Brute Force",
  "explanation": "47 failed SSH login attempts from the same IP strongly indicates a brute force attack targeting the admin account.",
  "recommended_action": "block_ip",
  "confidence": 0.95,
  "reasoning_steps": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ]
}

Possible recommended_action values: block_ip, kill_process, isolate_endpoint, alert_only, no_action
"""


class ThreatReasoner:
    """
    LLM-powered threat reasoning engine.
    Uses GPT-4o with chain-of-thought to assess anomalies.
    """

    def __init__(self, config):
        self.config = config
        self.client = AsyncOpenAI(api_key=config.OPENAI_API_KEY)
        logger.info(f"ThreatReasoner initialized with model: {config.LLM_MODEL}")

    async def assess(self, anomaly: dict) -> dict:
        """
        Sends the anomaly to the LLM for threat reasoning.
        Returns structured threat assessment.
        """
        # Pre-enrich with MITRE info as context
        mitre_info = get_mitre_info(anomaly.get("type", "unknown"))

        user_message = f"""
Analyze this security event:

Event Type: {anomaly.get('type')}
Source IP/Host: {anomaly.get('source')}
Raw Log: {anomaly.get('raw')}
Threat Score: {anomaly.get('threat_score')}
Initial Severity: {anomaly.get('severity')}
Timestamp: {anomaly.get('timestamp')}

Known MITRE Context:
- Tactic: {mitre_info['tactic']}
- Technique: {mitre_info['technique']}
- Suggested Mitigation: {mitre_info['mitigation']}

Provide your full chain-of-thought threat assessment in JSON.
"""

        try:
            logger.info("🧠 Sending event to LLM for reasoning...")
            response = await self.client.chat.completions.create(
                model=self.config.LLM_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=self.config.MAX_TOKENS,
                temperature=0.2,  # Low temp for consistent security analysis
                response_format={"type": "json_object"}
            )

            content = response.choices[0].message.content
            assessment = json.loads(content)

            # Merge with original anomaly data
            assessment["event_id"] = anomaly.get("event_id")
            assessment["event_type"] = anomaly.get("type")
            assessment["source"] = anomaly.get("source")
            assessment["timestamp"] = anomaly.get("timestamp")
            assessment["raw_log"] = anomaly.get("raw")

            logger.info(f"✅ LLM Assessment: {assessment['severity']} | {assessment['mitre_tactic']}")
            return assessment

        except Exception as e:
            logger.error(f"LLM reasoning failed: {e}")
            # Fallback to rule-based assessment
            return self._fallback_assessment(anomaly, mitre_info)

    def _fallback_assessment(self, anomaly: dict, mitre_info: dict) -> dict:
        """Fallback when LLM is unavailable — uses rule-based logic."""
        logger.warning("Using fallback rule-based assessment (LLM unavailable)")
        return {
            "event_id": anomaly.get("event_id"),
            "event_type": anomaly.get("type"),
            "source": anomaly.get("source"),
            "timestamp": anomaly.get("timestamp"),
            "raw_log": anomaly.get("raw"),
            "severity": anomaly.get("severity", "HIGH"),
            "mitre_tactic": mitre_info["tactic"],
            "mitre_technique": mitre_info["technique"],
            "explanation": f"Rule-based detection: {mitre_info['description']}",
            "recommended_action": "alert_only",
            "confidence": 0.70,
            "reasoning_steps": ["LLM unavailable — used rule-based fallback"],
        }
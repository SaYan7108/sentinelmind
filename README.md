# 🛡️ SentinelMind
### Autonomous Cyber Threat Detection & Response using Agentic AI

> **Hack & Break: Generative AI & Cybersecurity Innovation Challenge**
> Theme: **Agentic AI** | IIT Bombay

## 📸 Live Dashboard Preview

![Uploading image.png…]()


> Real-time threat monitoring dashboard — showing live threat events, MITRE ATT&CK mappings, autonomous actions, and AI reasoning traces.

---

## 🚨 Problem Statement

Security Operations Centers (SOCs) are overwhelmed:

- **10,000+ alerts/day** flood analyst teams — most are false positives
- **280 days** average time to detect and contain a breach *(IBM Cost of a Data Breach, 2023)*
- **70% of alerts** are noise — wasting skilled analyst hours
- **3.4 million** cybersecurity professionals short globally

> The gap between threat speed and human response is widening every year.

---

## 💡 Solution: SentinelMind

SentinelMind is an **autonomous AI agent** that monitors, reasons, and responds to cyber threats in real time — without waiting for human intervention.

```
[System Logs / Network Traffic]
          ↓
   [Anomaly Detector]          ← ML-based threat scoring
          ↓
  [LLM Reasoning Engine]  ←→  [MITRE ATT&CK Knowledge Base]
          ↓
  [Autonomous Response]        ← block_ip | kill_process | isolate_endpoint
          ↓
  [Audit Trail + Dashboard]    ← Plain-English explanation for every decision
```

---

## ⚙️ How It Works

| Step | Module | What It Does |
|------|--------|-------------|
| 01 | **Monitor** | Ingests system logs, network traffic, and process events in real time |
| 02 | **Detect** | Scores events with ML heuristics — filters noise from real threats |
| 03 | **Reason** | LLM chain-of-thought maps threat to MITRE ATT&CK tactic + assesses severity |
| 04 | **Respond** | Autonomously executes: block IP, kill process, isolate endpoint, or alert SOC |
| 05 | **Audit** | Every decision logged in plain English — full traceability and trust |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent Orchestration | LangGraph / AutoGen |
| LLM Reasoning | GPT-4o / Claude 3.5 / Mistral |
| Threat Intelligence | MITRE ATT&CK Framework |
| Log Ingestion | Python — Watchdog, Scapy, psutil |
| Response Layer | Python scripts — iptables, process control |
| Backend API | FastAPI + SQLite audit log |
| Dashboard | React + TailwindCSS |

---

## 📁 Project Structure

```
sentinelmind/
├── agent/
│   ├── monitor.py          # Real-time log & network event streaming
│   ├── detector.py         # ML-based anomaly scoring engine
│   ├── reasoner.py         # GPT-4o chain-of-thought threat reasoning
│   ├── responder.py        # Autonomous response + SQLite audit log
│   └── mitre_mapper.py     # MITRE ATT&CK tactic/technique mapping
├── dashboard/
│   └── index.html          # React live monitoring dashboard
├── scripts/
│   └── demo.py             # End-to-end attack simulation demo
├── docs/
│   └── dashboard-preview.png
├── api.py                  # FastAPI backend serving dashboard data
├── main.py                 # Main agent pipeline entry point
├── config.py               # All configuration and settings
└── requirements.txt
```

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/sentinelmind.git
cd sentinelmind

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your OpenAI API key in config.py
OPENAI_API_KEY = "your-api-key-here"

# 5. Run the demo (no real logs needed)
python scripts/demo.py

# 6. Start the API server
uvicorn api:app --reload --port 8000

# 7. Open the dashboard
# Open dashboard/index.html in your browser
```

---

## 🎮 Demo Output

```
==================================================
  🛡️  SentinelMind - DEMO MODE
==================================================

──────────────────────────────────────────────────
📥 EVENT: FAILED_LOGIN from 192.168.1.105
   Raw: Failed password for admin from 192.168.1.105 port 22 ssh2
   ⚠️  Anomaly Score: 0.87 | Severity: HIGH
   🧠 Sending to LLM for reasoning...
   📌 Tactic: Credential Access | Technique: T1110 - Brute Force
   💬 47 failed SSH login attempts from the same IP strongly
      indicates a brute force attack targeting the admin account.
   🔍 Reasoning Steps:
      → Step 1: 47 failed attempts in 2 minutes is anomalous
      → Step 2: Target is admin account — high value
      → Step 3: Single source IP confirms brute force pattern
   🚨 ACTION TAKEN: block_ip — IP 192.168.1.105 blocked via iptables

──────────────────────────────────────────────────
📥 EVENT: DATA_EXFILTRATION from 172.16.0.10
   ⚠️  Anomaly Score: 0.97 | Severity: CRITICAL
   🚨 ACTION TAKEN: isolate_endpoint — Host isolated from network
```

---

## 🗺️ MITRE ATT&CK Coverage

| Event Type | Tactic | Technique | Auto-Action |
|------------|--------|-----------|-------------|
| Brute Force Login | Credential Access | T1110 | Block IP |
| Port Scan | Reconnaissance | T1046 | Block IP |
| Data Exfiltration | Exfiltration | T1048 | Isolate Host |
| Privilege Escalation | Privilege Escalation | T1548 | Kill Process |
| Suspicious Process | Execution | T1059 | Kill Process |

---

## 📊 Impact

| Metric | Traditional SOC | SentinelMind |
|--------|----------------|--------------|
| Alert Response Time | 2–8 hours | **< 5 seconds** |
| False Positive Triage | Manual — 70% noise | **Auto-filtered by AI** |
| 24/7 Coverage | Requires staff rotations | **Always on, never tired** |
| Threat Explanation | Analyst writes report | **Auto-generated audit** |

---

## 🔌 API Endpoints

Once the FastAPI server is running at `http://localhost:8000`:

| Endpoint | Description |
|----------|-------------|
| `GET /api/events` | Returns all threat events from audit log |
| `GET /api/stats` | Returns summary stats for dashboard |
| `GET /api/events/{event_id}` | Returns single event with full reasoning trace |

---

## 👥 Team

| Name | Role |
|------|------|
| Sayan | AI Agent & Backend Development |
| Debosmita | Frontend Dashboard & Research |

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">

**Built with ❤️ for Hack & Break — IIT Bombay**

*Agentic AI Theme | Autonomous Cybersecurity*

</div>

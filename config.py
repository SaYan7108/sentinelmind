"""
SentinelMind - Configuration
"""

import os

class Config:
    # LLM Settings
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "sayandebosmita2109")
    LLM_MODEL = "gpt-4o"
    MAX_TOKENS = 1000

    # Monitoring Settings
    LOG_FILE_PATH = "./logs/sample_logs/system.log"
    MONITOR_INTERVAL = 2  # seconds

    # Threat Thresholds
    ANOMALY_THRESHOLD = 0.75
    HIGH_SEVERITY_SCORE = 0.85
    CRITICAL_SEVERITY_SCORE = 0.95

    # Response Settings
    AUTO_BLOCK_ENABLED = True
    AUTO_KILL_PROCESS_ENABLED = True
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "soc@yourcompany.com")

    # Database
    DB_PATH = "./sentinelmind.db"

    # Dashboard
    DASHBOARD_PORT = 8080
    API_PORT = 8000
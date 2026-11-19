# config.py
from __future__ import annotations
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

APP_NAME = "IDS Dashboard"
ENV = os.getenv("IDS_ENV", "dev")  # dev|prod

# Session
SESSION_TTL_SECONDS = int(os.getenv("IDS_SESSION_TTL", "1800"))  # 30 min
SESSION_ROTATE_ON_LOGIN = True

# Secrets (use .env in dev, environment vars in prod)
APP_SECRET = os.getenv("IDS_APP_SECRET", "CHANGE_ME_DEV_ONLY")

# AI
OLLAMA_MODEL = os.getenv("IDS_OLLAMA_MODEL", "").strip()
ADMIN_PASSWORD_CONFIGURED = bool(os.getenv("IDS_ADMIN_HASH", "").strip())

# Firewall safety
ALLOW_REAL_FIREWALL = os.getenv("IDS_ALLOW_REAL_FIREWALL", "0") == "1"

"""Configuration loader for Website Security Posture Checker.

Decouples environment variables and settings using python-dotenv.
"""
from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Automatically load .env if present
load_dotenv(BASE_DIR / ".env")

# Server settings
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
DEBUG = os.environ.get("DEBUG", "false").lower() in {"1", "true", "yes"}

# Google Safe Browsing API (Threat intelligence)
# Free key: https://console.cloud.google.com/apis/credentials
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

# AI Advisor Settings - Prioritizes Free Tier Models
# Google Gemini API (Recommended Free Tier - https://aistudio.google.com/app/apikey)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

# Groq API (High-speed Free Tier - https://console.groq.com/keys)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

# OpenAI API (Optional Fallback - https://platform.openai.com/api-keys)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# Scanner constraints
MAX_CONTENT_LENGTH = 100_000
MAX_BODY_BYTES = 512_000
MAX_FILE_BYTES = 64_000
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = (3.05, 5)
RATE_INTERVAL = 2.0
ADVICE_RATE_INTERVAL = 4.0
MAX_CONCURRENT_ASSESSMENTS = 4

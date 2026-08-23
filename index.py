"""Vercel serverless entry point.

Vercel's Python runtime auto-detects the ASGI `app` object below.
All /api/* requests are routed here by vercel.json; the static UI is served
from /public by Vercel's CDN.
"""

import os
import sys

# Make the project root importable inside the serverless bundle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app  # noqa: E402  (FastAPI ASGI application)

# Vercel discovers and serves this `app` automatically.

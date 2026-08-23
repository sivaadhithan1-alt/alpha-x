"""ScamCheck — FastAPI application.

Serves:
  GET  /                -> web UI
  GET  /api/health      -> liveness / engine version
  GET  /api/samples     -> curated demo messages
  POST /api/analyze     -> risk analysis endpoint
  GET  /docs            -> auto-generated Swagger UI (great for judging)
"""

import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.detector import analyze_message, ENGINE_VERSION
from backend.samples import SAMPLES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(
    title="ScamCheck — Opportunity Verification API",
    description=(
        "Explainable risk scoring for internship/job offers received over "
        "WhatsApp, email, or social media."
    ),
    version=ENGINE_VERSION,
)


class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=10, max_length=10000,
                         description="Full text of the opportunity message")
    sender_email: Optional[str] = Field(
        None, description="Email address the message claims to be from (optional)"
    )


@app.get("/api/health")
def health():
    return {"status": "ok", "engine": "ScamCheck", "engine_version": ENGINE_VERSION}


@app.get("/api/samples")
def samples():
    """Four curated examples covering the full verdict range."""
    return [
        {k: s[k] for k in ("id", "label", "icon", "message", "sender_email")}
        for s in SAMPLES
    ]


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    text = req.message.strip()
    if len(text) < 10:
        raise HTTPException(status_code=400, detail="Message text is too short to analyze.")
    return analyze_message(text, req.sender_email)


# ---------------------------------------------------------------- Agent Mode

class AgentAnalyzeRequest(BaseModel):
    name: Optional[str] = ""
    organization: Optional[str] = ""
    role: Optional[str] = "other"          # recruiter | internship | mentor | course | event | other
    links: Optional[str] = ""              # emails / URLs, space or comma separated
    pitch: Optional[str] = ""              # their offer / message text
    fee: Optional[float] = None            # rupees, if any


class AgentReplyRequest(BaseModel):
    topic: str
    question: Optional[str] = ""
    reply: str = Field(..., min_length=1, max_length=10000)
    history: list = []                     # [{topic, reply}]
    fee: Optional[float] = None


@app.post("/api/agent/analyze")
def agent_analyze(req: AgentAnalyzeRequest):
    from backend.agent import analyze_submission
    return analyze_submission(
        name=req.name or "", organization=req.organization or "",
        role=req.role or "other", links=req.links or "",
        pitch=req.pitch or "", fee=req.fee,
    )


@app.post("/api/agent/reply")
def agent_reply(req: AgentReplyRequest):
    from backend.agent import analyze_reply
    return analyze_reply(
        topic=req.topic, question=req.question or "",
        reply=req.reply, history=req.history, fee=req.fee,
    )


# Static frontend (mounted last so /api/* routes win)
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

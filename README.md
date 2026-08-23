**Problem Statement 3 · Hackspora 2.0 · Built with ❤️ for student safety**

```markdown
# 🛡️ ScamCheck — Opportunity Verification Engine

> **Verify before you trust.**
> An AI-rule-based platform that protects students from internship & job scams —
> analyzes any opportunity message for red flags, and runs full due-diligence
> on the recruiter behind it.



🔗 **Live Demo:** https://scamcheck-2jrtdz17w-alpha-x9.vercel.app

---

## 🎯 The Problem

> *Hackspora 2.0 — Problem Statement 3:*
> *"Students receive internship and job opportunities through WhatsApp, email and
> social media but often struggle to identify suspicious offers. Build a system that
> analyses submitted opportunity details and generates a risk score with clear,
> understandable warning indicators."*

Every year, thousands of students lose money to **fake internship offers** —
"Pay ₹999 registration fee", "Guaranteed placement for ₹2,500", messages from
"Wipro HR" sent from a Gmail address. There was no instant, transparent way to
check before trusting. **ScamCheck fixes that in 5 seconds.**

## ✨ Features

### 📩 Mode 1 — Message Scanner
Paste any offer (WhatsApp forward, email, SMS) → get an instant **0–100 risk score**:

| Verdict | Score | Meaning |
|---|---|---|
| 🟢 Looks Safe | 0–30 | No significant red flags |
| 🟡 Proceed with Caution | 31–60 | Some warning signs — verify first |
| 🔴 High Risk — Likely Scam | 61–100 | Multiple strong scam indicators |

- **10 explainable rule families** — every flag shows *why* it fired and
  **highlights the exact sentences** in the original message
- Detects: fee demands 💰, OTP/Aadhaar/bank-detail requests 🪪, free-mailbox "HR"
  addresses 📧, sender↔company domain mismatches, unrealistic pay claims,
  urgency pressure ⏰, WhatsApp-only contact, shortened links, vague roles,
  unprofessional language
- **Trust signals reduce the score** (official domains, structured interview
  processes, explicit no-fee statements) — it never just flags everything

### 🕵️ Mode 2 — Agent Verify (unique differentiator)
Full due-diligence assistant for the *person/organization* behind the offer:

1. **Intake analysis** — pitch auto-scan, link/domain checks, unrealistic-claim
   detection ("guaranteed job", "100% placement", fake scarcity), fee-value
   verdict: **WORTH IT / MAYBE / NOT WORTH IT**
2. **Generated questions** — prioritized due-diligence questions (CIN/GST number,
   placement proof, fee breakup, payment channel, mentor identity, alumni
   references) with **ready-to-send message versions**
3. **Reply verification loop** — paste each reply; the agent classifies it as
   *specific / partial / evasive / pressure / contradicted / nonsense*, updates a
   **live credibility meter**, and generates the next best follow-up question
4. **Live verification** — validates **CIN & GSTIN official formats** instantly
   and performs **real HTTP checks** on shared links (reachable? page title?
   mentions the claimed company?)

## 🧠 How It Works

```
Message → Entity extraction (emails, links, phones, amounts)
        → Red-flag rules     (+weighted points)
        → Trust-signal rules (−weighted points)
        → clamp 0–100 → verdict band
        → explainable report with highlighted evidence
```

**Design principles:** explainable over black-box · deterministic & auditable ·
honest fallbacks (it says "verify manually" instead of guessing) · works with
zero external API keys.

## ⚖️ Scoring Rules (summary)

| Red flag | Pts | | Trust signal | Pts |
|---|---|---|---|---|
| Requests money (fees/deposits) | +30 | | Official company domain | −15 |
| Asks for OTP/Aadhaar/bank data | +25 | | Structured selection process | −10 |
| Free email for "official" HR | +20 | | Explicit no-fee statement | −5 |
| Unrealistic offer | +20 | | | |
| Domain ≠ claimed company | +15 | | | |
| Urgency / WhatsApp-only / suspicious links / vague role / ALL-CAPS | +10 | | | |

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | **Python · FastAPI** (REST API + auto Swagger docs) |
| Detection engine | **Rule-based regex + weighted scoring** (detector.py, agent.py, livecheck.py) |
| Live checks | **httpx** — real link fetching, CIN/GSTIN format validation |
| Frontend | **Single-page HTML/CSS/JS** — animated risk gauge, evidence highlighting, ambient video |
| Testing | **42 automated checks** (scanner + agent parity) |
| Deployment | **Vercel** (serverless Python + CDN static) |

## 📁 Project Structure

```
├── api/index.py          # Vercel serverless entry
├── backend/
│   ├── detector.py       # message-scam rule engine
│   ├── agent.py          # due-diligence agent (claims, questions, replies)
│   ├── livecheck.py      # CIN/GSTIN validation + live HTTP checks
│   ├── samples.py        # curated demo messages
│   └── main.py           # FastAPI app
├── public/index.html     # web UI (2 modes)
├── frontend/             # UI for local runs
├── tests/                # 18 scanner + 24 agent checks
├── requirements.txt
└── vercel.json
```

## 🚀 Run Locally

```bash
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000
# → http://localhost:8000        (app)
# → http://localhost:8000/docs   (Swagger API docs)
```

## ✅ Verification (judge-verifiable)

```bash
python3 tests/test_detector.py   # 18/18 PASS — scanner rules & verdict bands
python3 tests/test_agent.py      # 24/24 PASS — agent Q&A, evasion, contradictions
```

Every scoring rule is deterministic and covered by tests — judges can paste
any real message and audit exactly why it got its score.

## 🗺️ Roadmap

- [ ] ML layer (TF-IDF + Logistic Regression) blended 40/60 with rule score
- [ ] WHOIS domain-age + typo-squat (lookalike domain) detection
- [ ] Browser extension / WhatsApp-forward bot
- [ ] Multilingual scam phrase banks (Tamil, Hindi)
- [ ] Community-reported scam blacklist feed

## ⚠️ Disclaimer

ScamCheck is an automated screening aid. A "safe" result is **not** a guarantee —
always verify opportunities via official company websites, placement cells, or
published HR contacts before paying anyone.

## 👥 Team

| Member | Role |
|---|---|
|SIVA ADHITHAN M|SOFTWARE|
|ARAVIND A|PRESENTATION|
|SRIHARI S|R&D|
|ARJUN A|SOFTWARE|
|LOKESH|R&D|



# 🛡️ ScamCheck — Vercel deployment package

Opportunity verification engine (Hackspora 2.0 · Problem Statement 3):
**Message Scanner** (explainable scam risk scoring) + **Agent Verify**
(due-diligence question generator + reply verification with live web checks).

This package is pre-configured for **Vercel**: FastAPI runs as a Python
serverless function, the UI is served from the CDN, and live link/ID checks
work because serverless functions have outbound internet access.

## 📁 Structure

```
scamcheck-vercel/
├── api/index.py        # Vercel entry → serves the FastAPI app
├── backend/            # detector.py · agent.py · livecheck.py · samples.py · main.py
├── frontend/           # UI (used when running locally with uvicorn)
├── public/index.html   # UI (served by Vercel CDN at /)
├── requirements.txt    # fastapi, uvicorn, pydantic, httpx
└── vercel.json         # routes /api/* to the Python function
```

## 🚀 Deploy (2 minutes)

**Option A — Vercel CLI (no GitHub needed):**
```bash
npm install -g vercel
cd scamcheck-vercel
vercel          # first deploys a preview
vercel --prod   # production URL
```

**Option B — GitHub:**
1. Push this folder to a GitHub repo
2. vercel.com → *Add New Project* → import the repo
3. Framework preset: **Other** (no build command needed) → Deploy

No environment variables, build steps, or database required.

## ✅ After deploying — verify

- `https://<your-app>.vercel.app/` → UI loads
- `https://<your-app>.vercel.app/api/health` → `{"status":"ok",...}`
- Scanner → click 🔴 *Obvious Scam* sample → score 100
- Agent → analyze a suspicious pitch, paste a reply containing
  `CIN U74999TN2019PTC123456` and `google.com` → watch format validation
  + 🌐 live fetch rows appear

**Demo tip:** open `/api/health` once before presenting — it warms the
serverless function so the live demo is instant.

## 💻 Run locally (identical app)

```bash
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000
# → http://localhost:8000  (UI + API + /docs)
```

Run the test suites from the parent folder copy (`scamcheck/tests/`) or copy
them here; they are deployment-independent.

## 📜 Notes

- Live web checks (CIN/GSTIN format validation + real HTTP fetch of shared
  links) work on Vercel because functions can reach the internet. If a site
  blocks bots (HTTP 403), the app says so honestly instead of flagging it fake.
- Clearly-labeled offline fallbacks keep every verdict honest when a link
  cannot be fetched.

*Built for Hackspora 2.0 — FastAPI + explainable rule engine. MIT License.*

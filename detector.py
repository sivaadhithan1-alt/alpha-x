"""
ScamCheck — rule-based detection engine for internship / job scam screening.

Design goals
------------
1. Explainable : every flag carries the exact text spans that triggered it,
    so the UI can highlight them and judges can audit the verdict.
2. Deterministic: same input -> same output, no network dependency.
3. Extensible  : an ML layer can be blended in later (see README roadmap).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

ENGINE_VERSION = "1.0.0"
MAX_SCORE = 100

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.in",
    "hotmail.com", "outlook.com", "live.com", "msn.com", "rediffmail.com",
    "protonmail.com", "proton.me", "aol.com", "mail.com", "gmx.com",
    "icloud.com", "yandex.com",
}

SHORT_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "t.ly", "shorturl.at",
    "ow.ly", "is.gd", "goo.gl", "rebrand.ly", "buff.ly",
}

KNOWN_COMPANIES = {
    "tcs": "Tata Consultancy Services (TCS)",
    "tata consultancy services": "Tata Consultancy Services (TCS)",
    "tata consultancy": "Tata Consultancy Services (TCS)",
    "wipro": "Wipro",
    "infosys": "Infosys",
    "google": "Google",
    "microsoft": "Microsoft",
    "amazon": "Amazon",
    "flipkart": "Flipkart",
    "hcl": "HCL Technologies",
    "cognizant": "Cognizant",
    "accenture": "Accenture",
    "ibm": "IBM",
    "deloitte": "Deloitte",
    "tech mahindra": "Tech Mahindra",
    "reliance": "Reliance Industries",
    "zomato": "Zomato",
    "swiggy": "Swiggy",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "ola": "Ola",
    "capgemini": "Capgemini",
    "oracle": "Oracle",
    "adobe": "Adobe",
}

JOB_CONTEXT = re.compile(
    r"\b(internships?|interns?|jobs?|hiring|hired|recruit\w*|selected|shortlisted|"
    r"offers?|position|vacanc\w+|careers?|stipend|salary|openings?|candidates?|"
    r"placement|onboarding|opportunit\w+|apply|applying|hr|earn\w*|allowance)\b",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s\"'<>)\]]+|"
    r"\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|t\.ly|shorturl\.at|ow\.ly|"
    r"is\.gd|goo\.gl|rebrand\.ly|buff\.ly)/[^\s\"'<>)\]]+",
    re.IGNORECASE,
)
PHONE_RE = re.compile(
    r"(?:\+91[\s\-]?)?(?<!\d)[6-9]\d{9}(?!\d)|(?:\+\d{1,3}[\s\-]?)\d{10,12}"
)
AMOUNT_RE = re.compile(
    r"(?:rs\.?|₹|inr)\s*[\d,]+(?:\.\d+)?(?:\s*(?:k|thousand|lakh|lakhs|lac|lacs))?",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Rule pattern banks
# ---------------------------------------------------------------------------

PAYMENT_PATTERNS = [
    r"\b(registration|security|training|processing|joining|enrol{1,2}ment|"
    r"activation|verification|documentation|membership|subscription|booking)"
    r"\s+(fee|fees|deposit|charge|charges|amount|payment)\b",
    r"\b(fee|fees|deposit|charge|charges)\s+of\s+(rs\.?|₹|inr)\b",
    r"\b(pay|deposit|transfer|remit)\s+(a\s+)?(refundable\s+|small\s+|"
    r"one[-\s]?time\s+)?(rs\.?|₹|inr)\b",
    r"\b(refundable|adjustable)\s+(registration\s+|security\s+|caution\s+)?"
    r"(fee|fees|deposit|amount)\b",
    r"\bcaution\s+deposit\b",
    r"\badvance\s+(fee|payment|deposit)\b",
    r"\bwire\s+transfer\b",
]

SENSITIVE_PATTERNS = [
    r"\botp\b",
    r"\bone[-\s]?time\s+password\b",
    r"\baadha?ar\b(\s+card)?",
    r"\bpan\s+card\b",
    r"\bbank\s+(account|details|statement)\b",
    r"\baccount\s+(number|no\.?)\b",
    r"\bcvv\b",
    r"\bcard\s+(number|details)\b",
    r"\bupi\s+pin\b",
    r"\batm\s+(card|pin)\b",
    r"\bpassport\s+(details|number|copy)\b",
    r"\bshare\s+your\s+(password|pin)\b",
]

UNREALISTIC_PATTERNS = [
    r"\bno\s+interviews?\s+(required|needed|process)?\b",
    r"\bwithout\s+(any\s+)?interviews?\b",
    r"\bno\s+(prior\s+)?(experience|skills?|qualifications?)\s+(is\s+)?"
    r"(needed|required|necessary)\b",
    r"\b(100%|hundred\s+percent)\s+(guaranteed\s+)?(placement|job|selection|offer)\b",
    r"\bguaranteed\s+(job|jobs|income|placement|selection|offer|salary|earning)s?\b",
    r"\bdirect\s+(joining|selection|recruitment)\b",
    r"\bearn\s+(rs\.?|₹|inr)?\s?[\d,]+\s*(k|thousand|lakh|lakhs)?\s*"
    r"(per\s+|a\s+|/\s*)(day|daily)\b",
]

URGENCY_PATTERNS = [
    r"\b(only|just)\s+\d+\s+(slot|slots|seat|seats|position|positions|"
    r"opening|openings|vacancy|vacancies)\b",
    r"\blimited\s+(slot|slots|seat|seats|positions?|time|offer|period)\b",
    r"\blast\s+chance\b",
    r"\bact\s+now\b",
    r"\bhurry(\s*up)?\b",
    r"\bexpires?\s+(today|soon|tonight|tomorrow)\b",
    r"\bwithin\s+\d+\s+(hour|hours|hr|hrs)\b",
    r"\bapply\s+(immediately|now|fast|soon|today)\b",
    r"\bdon'?t\s+miss\b",
    r"\boffer\s+valid\s+(only\s+)?(for|till|until)\b",
]

MESSAGING_PATTERNS = [
    r"\b(whatsapp|whats\s?app|telegram)\b.{0,45}"
    r"\b(apply|contact|reach|ping|message|text|share|send|call|hr)\b",
    r"\b(apply|contact|reach|ping|message|text|share|send|call)\b.{0,45}"
    r"\b(whatsapp|whats\s?app|telegram)\b",
]

VAGUE_ROLE_PATTERNS = [
    r"\bdata\s+entry\b",
    r"\b(simple\s+|easy\s+)?typing\s+(job|work)\b",
    r"\bcopy[\s-]?paste\b",
    r"\bform[\s-]?filling\b",
    r"\bsms\s+(sending|job)\b",
    r"\bad[\s-]?posting\b",
]

MISSPELL_PATTERNS = [
    r"\b(recieve|gurantee[ds]?|adress|payement|benifit|eligable|salery|"
    r"immediatly|oppertunit\w*|securty|govt\.?\s+certified)\b",
]

STRUCTURED_PATTERNS = [
    r"\b(online|written|aptitude|coding)\s+(assessment|test)\b",
    r"\b(technical|hr|telephonic)\s+(round|interview)s?\b",
    r"\brounds?\s+of\s+(interviews?|tests?|the\s+selection)\b",
    r"\bselection\s+process\b",
    r"\binterview\s+(process|schedule|panel)\b",
]

NO_FEE_PATTERNS = [
    r"\bnever\s+(ask|asks|asked|request|requests|requested|charge|charges|"
    r"demand|demands)\b[^.\n]{0,70}\b(fee|fees|payment|deposit|money)\b",
    r"\bfree\s+of\s+(cost|charge)\b",
    r"\bno\s+(registration|security|joining|hidden)\s+(fee|fees|charges?)\b",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _spans(patterns, text, limit=4):
    """Return non-overlapping match spans [{start,end,text}], max `limit`."""
    out = []
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            s, e = m.span(0)
            if any(not (e <= o["start"] or s >= o["end"]) for o in out):
                continue
            out.append({"start": s, "end": e, "text": text[s:e]})
            if len(out) >= limit:
                return sorted(out, key=lambda d: d["start"])
    return sorted(out, key=lambda d: d["start"])


def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def _email_domain(email):
    return email.split("@")[-1].strip().lower()


def _url_domain(url):
    u = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)
    u = re.sub(r"^www\.", "", u, flags=re.IGNORECASE)
    return u.split("/")[0].split(":")[0].lower()


def _companies_in(text):
    low = text.lower()
    hits = []
    for token, display in KNOWN_COMPANIES.items():
        if re.search(r"\b" + re.escape(token) + r"\b", low):
            if display not in [d for _, d in hits]:
                hits.append((token, display))
    return hits


def _domain_matches_company(domain):
    norm = re.sub(r"[^a-z0-9]", "", domain)
    for token, display in KNOWN_COMPANIES.items():
        if token.replace(" ", "") in norm:
            return display
    return None


def _unrealistic_amount_spans(text, limit=4):
    """Flag implausible pay claims, e.g. '₹5,000/day' or '₹60,000/month'."""
    spans = []
    for m in re.finditer(
        r"(?:rs\.?|₹|inr)\s*([\d,]+(?:\.\d+)?)\s*"
        r"(k|thousand|lakh|lakhs|lac|lacs)?", text, re.IGNORECASE,
    ):
        try:
            value = float(m.group(1).replace(",", ""))
        except ValueError:
            continue
        mult = (m.group(2) or "").lower()
        if mult in ("k", "thousand"):
            value *= 1_000
        elif mult.startswith(("lac", "lakh")):
            value *= 100_000
        window = text[m.end(): m.end() + 28].lower()
        pm = re.match(
            r"[\s/,()\-]*(?:per\s+|a\s+)?(day|daily|week|weekly|month|monthly)\b",
            window,
        )
        period = pm.group(1) if pm else None
        suspicious = (
            (period in ("day", "daily") and value >= 1500)
            or (period in ("week", "weekly") and value >= 12000)
            or (period in ("month", "monthly") and value >= 45000)
        )
        if suspicious:
            if not any(not (m.end() <= o["start"] or m.start() >= o["end"]) for o in spans):
                spans.append({"start": m.start(), "end": m.end(), "text": text[m.start():m.end()]})
        if len(spans) >= limit:
            break
    return spans


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_message(message: str, sender_email: Optional[str] = None) -> dict:
    text = message.strip()
    flags = []          # red flags (positive points)
    positives = []      # trust signals (negative points)

    urls = _dedupe([m.group(0).rstrip(".,;!") for m in URL_RE.finditer(text)])
    body_emails = _dedupe([m.group(0) for m in EMAIL_RE.finditer(text)])
    phones = _dedupe([m.group(0).strip() for m in PHONE_RE.finditer(text)])
    amounts = _dedupe([m.group(0).strip() for m in AMOUNT_RE.finditer(text)])
    companies = _companies_in(text)
    has_job_context = bool(JOB_CONTEXT.search(text))

    sender = (sender_email or "").strip().lower()
    if sender and not EMAIL_RE.fullmatch(sender):
        sender = ""  # ignore malformed sender input

    # -------------------------------------------------------------- payments
    hits = _spans(PAYMENT_PATTERNS, text)
    if hits:
        flags.append({
            "id": "payment_request",
            "title": "Requests money from the candidate",
            "points": 30,
            "explanation": (
                "Genuine employers never charge registration, training, or "
                "security fees to candidates. Any 'refundable deposit' demand "
                "is the single strongest scam indicator."
            ),
            "matches": hits,
        })

    # ------------------------------------------------------ sensitive info
    hits = _spans(SENSITIVE_PATTERNS, text)
    if hits:
        flags.append({
            "id": "sensitive_info_request",
            "title": "Asks for sensitive personal data",
            "points": 25,
            "explanation": (
                "Requests for OTPs, Aadhaar, PAN, or bank/card details at the "
                "offer stage are a hallmark of identity-theft scams."
            ),
            "matches": hits,
        })

    # -------------------------------------------------- sender / email checks
    email_candidates = ([sender] if sender else []) + [
        e for e in body_emails if e.lower() != sender
    ]
    checked_email, checked_domain = None, None
    official_evidence = None

    for em in email_candidates:
        dom = _email_domain(em)
        if dom in FREE_EMAIL_PROVIDERS and has_job_context:
            checked_email, checked_domain = em, dom
            if companies:
                names = ", ".join(d for _, d in companies)
                expl = (
                    f"The message claims an official opportunity but the contact "
                    f"address '{em}' is a free public mailbox (@{dom}). "
                    f"{names} and similar firms email only from corporate domains "
                    f"(e.g. name@company.com)."
                )
            else:
                expl = (
                    f"The contact address '{em}' is a free public mailbox "
                    f"(@{dom}). Legitimate recruiters use their organization's "
                    f"domain; lone Gmail/Yahoo addresses are common with scams."
                )
            flags.append({
                "id": "free_email_provider",
                "title": "Free email provider for official communication",
                "points": 20,
                "explanation": expl,
                "matches": _spans([re.escape(em)], text, limit=1),
            })
            break
        match = _domain_matches_company(dom)
        if match:
            official_evidence = ("email", em, match)
            checked_email, checked_domain = em, dom
            break
        checked_email, checked_domain = em, dom  # remember corporate-looking one

    if not official_evidence and urls:
        for u in urls:
            match = _domain_matches_company(_url_domain(u))
            if match:
                official_evidence = ("link", u, match)
                break

    # domain mismatch (company named, corporate-style domain, but not theirs)
    if companies and checked_domain and checked_domain not in FREE_EMAIL_PROVIDERS:
        if not official_evidence:
            names = ", ".join(d for _, d in companies)
            flags.append({
                "id": "domain_mismatch",
                "title": "Sender domain does not match the claimed company",
                "points": 15,
                "explanation": (
                    f"The message names {names}, but the address "
                    f"'{checked_email}' belongs to an unrelated domain "
                    f"({checked_domain}). Verify the opening on the company's "
                    f"official careers page."
                ),
                "matches": _spans([re.escape(checked_email)], text, limit=1),
            })

    # ------------------------------------------------------- unrealistic offer
    hits = _spans(UNREALISTIC_PATTERNS, text) + _unrealistic_amount_spans(text)
    if hits:
        merged, seen = [], []
        for h in sorted(hits, key=lambda d: d["start"]):
            if any(not (h["end"] <= o["start"] or h["start"] >= o["end"]) for o in merged):
                continue
            merged.append(h)
        flags.append({
            "id": "unrealistic_offer",
            "title": "Offer sounds too good to be true",
            "points": 20,
            "explanation": (
                "High pay with 'no interview', 'no experience needed', or "
                "'guaranteed selection' claims do not match how real hiring "
                "works — scammers use them as bait."
            ),
            "matches": merged[:4],
        })

    # -------------------------------------------------------------- urgency
    hits = _spans(URGENCY_PATTERNS, text)
    if hits:
        flags.append({
            "id": "urgency_pressure",
            "title": "Artificial urgency / pressure tactics",
            "points": 10,
            "explanation": (
                "Countdowns and 'limited slots' pressure you into acting before "
                "verifying. Authentic recruiters allow reasonable time to respond."
            ),
            "matches": hits,
        })

    # -------------------------------------------------- messaging-only contact
    hits = _spans(MESSAGING_PATTERNS, text)
    if hits:
        flags.append({
            "id": "messaging_only_contact",
            "title": "WhatsApp / Telegram-only communication",
            "points": 10,
            "explanation": (
                "Recruitment handled purely over WhatsApp/Telegram leaves no "
                "verifiable corporate trail — a frequent scam pattern."
            ),
            "matches": hits,
        })

    # --------------------------------------------------------- suspicious links
    bad_links = []
    for u in urls:
        dom = _url_domain(u)
        if dom in SHORT_URL_DOMAINS:
            bad_links.append(u)
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}", dom):
            bad_links.append(u)
        elif u.lower().startswith("http://"):
            bad_links.append(u)
    if bad_links:
        flags.append({
            "id": "suspicious_links",
            "title": "Shortened or suspicious links",
            "points": 10,
            "explanation": (
                "Shortened (bit.ly etc.), IP-based, or non-HTTPS links hide the "
                "real destination and are widely used in phishing campaigns."
            ),
            "matches": _spans([re.escape(u) for u in bad_links], text, limit=4),
        })

    # ------------------------------------------------------------- vague role
    hits = _spans(VAGUE_ROLE_PATTERNS, text)
    if hits:
        flags.append({
            "id": "vague_job_role",
            "title": "Vague or generic job description",
            "points": 10,
            "explanation": (
                "'Data entry', 'typing work' or 'form filling' offers with no "
                "skill requirements are classic work-from-home scam lures."
            ),
            "matches": hits,
        })

    # ------------------------------------------------------------- language QA
    words = re.findall(r"[A-Za-z']+", text)
    caps = [w for w in words if len(w) >= 4 and w.isupper()]
    multi_bang = len(re.findall(r"!{2,}|\?{2,}", text))
    misspells = _spans(MISSPELL_PATTERNS, text)
    caps_ratio = len(caps) / max(len(words), 1)
    if caps_ratio >= 0.12 or multi_bang >= 2 or misspells:
        flags.append({
            "id": "unprofessional_language",
            "title": "Unprofessional language patterns",
            "points": 10,
            "explanation": (
                "Excessive ALL-CAPS, repeated exclamation marks, or spelling "
                "errors are uncommon in genuine corporate communication."
            ),
            "matches": (misspells + _spans([r"[A-Za-z' ]*!{2,}"], text, limit=2))[:4],
        })

    # ======================================================== trust signals
    if official_evidence:
        kind, value, company = official_evidence
        positives.append({
            "id": "official_domain",
            "title": "Contact matches an official company domain",
            "points": -15,
            "explanation": (
                f"The {kind} '{value}' is hosted on a domain matching "
                f"{company} — consistent with genuine communication."
            ),
            "matches": _spans([re.escape(value)], text, limit=1),
        })

    hits = _spans(STRUCTURED_PATTERNS, text)
    if hits:
        positives.append({
            "id": "structured_process",
            "title": "Describes a structured selection process",
            "points": -10,
            "explanation": (
                "Assessments and interview rounds indicate a real hiring "
                "pipeline; scams usually skip them entirely."
            ),
            "matches": hits,
        })

    hits = _spans(NO_FEE_PATTERNS, text)
    if hits:
        positives.append({
            "id": "no_fee_statement",
            "title": "Explicitly states no fees are charged",
            "points": -5,
            "explanation": (
                "Many genuine employers state they never request payment. "
                "(A scammer could also write this — treat it as a minor "
                "positive signal only.)"
            ),
            "matches": hits,
        })

    # ======================================================== final verdict
    raw = sum(f["points"] for f in flags) + sum(p["points"] for p in positives)
    score = max(0, min(MAX_SCORE, raw))

    if score <= 30:
        verdict = {
            "level": "safe", "label": "Looks Safe", "color": "#10b981",
            "description": (
                "No significant scam indicators detected. You should still "
                "verify the opportunity independently via official channels."
            ),
        }
    elif score <= 60:
        verdict = {
            "level": "caution", "label": "Proceed with Caution", "color": "#f59e0b",
            "description": (
                "Some warning signs detected. Cross-check the sender, domain, "
                "and the opening on the organization's official careers page "
                "before responding."
            ),
        }
    else:
        verdict = {
            "level": "high_risk", "label": "High Risk — Likely Scam", "color": "#f43f5e",
            "description": (
                "Multiple strong scam indicators. Do NOT pay any money and do "
                "not share documents, OTPs, or bank details."
            ),
        }

    flags.sort(key=lambda f: f["points"], reverse=True)

    return {
        "engine_version": ENGINE_VERSION,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "max_score": MAX_SCORE,
        "verdict": verdict,
        "flags": flags,
        "positive_signals": positives,
        "extracted": {
            "sender": sender or None,
            "emails": body_emails,
            "urls": urls,
            "phones": phones,
            "amounts": amounts,
        },
        "summary": (
            f"{len(flags)} red flag(s), {len(positives)} trust signal(s) — "
            f"risk score {score}/{MAX_SCORE}."
        ),
        "disclaimer": (
            "Automated heuristic screening. Always verify opportunities through "
            "official company channels before taking action."
        ),
    }

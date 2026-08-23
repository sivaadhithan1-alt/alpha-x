"""
ScamCheck Agent Mode — offline verification assistant for people / mentors /
courses / internships / services / events / organizations.

What it does
------------
1. Analyzes an intake (name, org, links, pitch text, fee) using the ScamCheck
   detector plus unrealistic-claim and link checks.
2. Produces a prioritized list of due-diligence questions + ready-to-send
   messages, each tied to a concrete finding.
3. Analyzes each pasted reply for topical relevance, evasion, pressure tactics,
   contradictions with earlier replies, and evidence content — then produces
   the next best follow-up question.

Honesty note
------------
This engine runs fully offline (hackathon-safe). It performs *consistency and
red-flag* analysis on replies; identifiers/links contained in replies are
surfaced for the user to confirm on official portals (MCA, LinkedIn...).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from backend.detector import analyze_message
from backend import livecheck

AGENT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Unrealistic-claim detection
# ---------------------------------------------------------------------------

UNREALISTIC_CLAIMS = [
    ("guaranteed_outcome",
     r"\bguaranteed\s+(job|jobs|placement|internship|selection|offer|income)s?\b",
     "Guaranteed job / internship / placement",
     "Employment outcomes can never be guaranteed by a third party."),
    ("hundred_percent",
     r"\b100\s?%\s*(placement|job|selection|guarantee|assurance|success|genuine)\b",
     '"100%" outcome claims',
     "Absolute outcome claims are a standard marketing/scam pattern."),
    ("instant_expert",
     r"(become\s+(an?\s+)?expert|master(?:ing)?\s+\w+|zero\s+to\s+hero)\s+in\s+\d+\s+(days?|weeks?)",
     '"Become an expert in a few days"',
     "Skill acquisition timelines measured in days are unrealistic."),
    ("guaranteed_salary",
     r"(guaranteed|assured)\s+(salary|package|ctc)\b|\b\d+(\.\d+)?\s*(lpa|lakh)\s+(guaranteed|assured)|guaranteed\s+\d+(\.\d+)?\s*(lpa|lakh)",
     "Guaranteed high salary / package",
     "Salary packages cannot be guaranteed before any selection process."),
    ("fake_scarcity",
     r"only\s+\d+\s+(seats?|slots?)|last\s+\d+\s+(seats?|slots?)|limited\s+(seats?|slots?)\s+(left|available)",
     "Fake scarcity",
     "Artificial seat limits are used to rush decisions."),
    ("unverifiable_association",
     r"(associated|partnered|collaboration|tie[\s-]?up)\s+with\s+(google|microsoft|amazon|iit|iisc|isro|tcs|infosys|wipro|meta|ibm)",
     "Unverifiable big-brand association",
     "Brand-name associations without official documentation are unverifiable claims."),
]

# ---------------------------------------------------------------------------
# Question bank (prioritized; keywords drive reply analysis)
# ---------------------------------------------------------------------------

QUESTION_BANK = {
    "company_registration": {
        "priority": 100,
        "question": "Could you share your company's CIN (Corporate Identification Number) or GST number, and the link to your official website and LinkedIn page?",
        "message": "Hi! Before I proceed, I'd like to verify the organization. Could you share the company's CIN / GST number along with the official website and LinkedIn page? These can be cross-checked on the MCA/GST portals in a couple of minutes.",
        "why": "The organization could not be matched to an official domain from the information provided.",
        "hint": "cin", "keywords": ["cin", "gst", "udyam", "msme", "registered", "incorporat", "llp", "ltd", "pvt", "http", "www", ".com", ".in", "linkedin", "roc", "mca"],
        "drill": "Please share the exact CIN or GST number itself (not a general assurance) — I will verify it on the official portal.",
    },
    "placement_proof": {
        "priority": 90,
        "question": "Can you share the last batch's placement statistics — number of students, companies, and a sample offer letter (with personal details masked)?",
        "message": "Thanks! Could you also share verifiable placement data for the recent batch — count of placed students, recruiting companies, and a masked sample offer letter? Genuine providers usually publish this.",
        "why": "The pitch contains placement/job-outcome claims that need evidence.",
        "hint": "placement statistics",
        "keywords": ["placed", "placement", "companies", "offer letter", "batch", "students", "%", "recruiter", "hired", "ctc", "lpa"],
        "drill": "A percentage alone isn't verifiable — could you share the actual count, company names, or a masked offer letter?",
    },
    "fee_breakdown": {
        "priority": 88,
        "question": "What exactly does the fee cover, is there a written invoice and refund policy, and are there any additional or recurring charges?",
        "message": "Before paying anything, could you share the complete fee breakup on your official letterhead/website, including refund policy and any extra charges? I'd also need a proper GST invoice for the payment.",
        "why": "A fee is involved, so every rupee must be mapped to a deliverable.",
        "hint": "fee breakdown",
        "keywords": ["refund", "invoice", "gst", "breakup", "includes", "cover", "receipt", "gstin", "policy", "charge"],
        "drill": "Please send the fee breakup and refund policy in writing (document or official link), not just verbally.",
    },
    "payment_channel": {
        "priority": 86,
        "question": "Will the payment go to the company's official bank account or payment gateway with an invoice — not a personal UPI/phone number?",
        "message": "For the payment step: I can only pay against the company's official bank account or a proper payment gateway with invoice. Please confirm the account is in the company's registered name.",
        "why": "Personal UPI/UPI-to-individual collection is a classic scam channel.",
        "hint": "payment channel",
        "keywords": ["bank", "account", "gateway", "invoice", "receipt", "company", "razorpay", "ifsc", "official"],
        "drill": "Kindly share the beneficiary name and IFSC so I can confirm the account belongs to the registered company.",
    },
    "mentor_and_project": {
        "priority": 80,
        "question": "Who exactly will mentor me (their name and LinkedIn profile), and what concrete project/deliverable will I complete by the end?",
        "message": "Could you tell me who my mentor will be (name + LinkedIn) and the exact project or deliverable I would complete? I'd like to evaluate the learning value specifically.",
        "why": "The pitch does not identify concrete people or deliverables.",
        "hint": "mentor and deliverable",
        "keywords": ["mentor", "linkedin", "project", "deliverable", "github", "experience", "engineer", "profile", "name"],
        "drill": "Please share the mentor's actual name and LinkedIn/GitHub profile — 'experienced professionals' is not verifiable.",
    },
    "official_offer_letter": {
        "priority": 78,
        "question": "Will I receive an official offer letter from the company's email domain before any payment, mentioning role, duration, stipend, and supervisor?",
        "message": "Could you issue the internship offer letter from the official company email domain before any payment, with role, duration, stipend, and supervisor clearly stated?",
        "why": "Legitimate onboarding always precedes payment; scammers reverse the order.",
        "hint": "offer letter",
        "keywords": ["offer letter", "letter", "domain", "email", "stipend", "duration", "supervisor", "role", "yes"],
        "drill": "Please send the offer letter from the official company email (not Gmail/WhatsApp) before we discuss payment.",
    },
    "alumni_reference": {
        "priority": 72,
        "question": "Could you connect me with 1–2 past participants so I can hear their real experience and outcomes?",
        "message": "Would it be possible to speak with one or two past participants? A quick chat with alumni would help me decide confidently.",
        "why": "Independent references expose inflated marketing claims.",
        "hint": "alumni references",
        "keywords": ["alumni", "student", "participant", "reference", "connect", "share", "contact", "linkedin"],
        "drill": "A LinkedIn profile or direct introduction to any past participant would work — could you share one?",
    },
    "technical_stack": {
        "priority": 65,
        "question": "What is the exact tech stack and syllabus/project outline (tools, versions, weekly plan)? Can you share a sample of the actual learning material?",
        "message": "Could you share the exact syllabus/tech stack with a weekly plan, and a small sample of the actual course material or a demo class? That will let me judge the depth before enrolling.",
        "why": "Coursera/YouTube repackaging is common; samples reveal real depth.",
        "hint": "syllabus and sample material",
        "keywords": ["syllabus", "stack", "week", "module", "python", "react", "node", "ml", "demo", "sample", "curriculum", "project"],
        "drill": "Please share a concrete week-by-week plan and one sample lesson — generic lists like 'HTML, CSS, AI' are not enough.",
    },
}

DEFAULT_QUEUE = [
    "company_registration", "official_offer_letter", "fee_breakdown",
    "payment_channel", "placement_proof", "mentor_and_project",
    "alumni_reference", "technical_stack",
]

TECH_HINT = re.compile(r"\b(ai|ml|machine learning|deep learning|python|data science|"
                       r"web ?dev|full[\s-]?stack|react|node|java|cloud|iot|embedded)\b", re.I)

# ---------------------------------------------------------------------------
# Reply-analysis pattern banks
# ---------------------------------------------------------------------------

EVASION_PATTERNS = [
    r"\btrust me\b", r"\bbelieve me\b", r"\bdon'?t worry\b", r"\bno need to (worry|check|verify)\b",
    r"\bwe (are|r) (100%\s*)?(genuine|legit|trusted)\b", r"\b100% genuine\b",
    r"\bjust (pay|join|enroll)\b", r"\beveryone (is|has) (joining|paying)\b",
]
PRESSURE_PATTERNS = [
    r"\bpay\s+(now|today|immediately|first)\b", r"\bonly \d+ (seats?|slots?)\b",
    r"\blast chance\b", r"\boffer expires\b", r"\bwithin \d+ hours?\b",
    r"\bseats? (are )?filling\b",
]
FREE_CLAIM_PATTERNS = [r"\b(no fee|free of (cost|charge)|completely free|nothing to pay|no payment)\b"]
FEE_DEMAND_PATTERNS = [r"(rs\.?|₹|inr)\s*[\d,]+", r"\b(fee|payment|deposit|pay)\b.{0,30}(rs\.?|₹|inr)|\b(rs\.?|₹|inr)\s*[\d,]+.{0,30}(fee|payment|deposit)"]


def _credibility_band(v: int) -> str:
    if v >= 70:
        return "High"
    if v >= 40:
        return "Medium"
    return "Low"


def _looks_nonsense(text: str) -> bool:
    """Detect keyboard-mash / random text: very low vowel ratio + long junk words."""
    words = re.findall(r"[A-Za-z]{4,}", text)
    if len(words) < 4:
        return False
    letters = re.sub(r"[^a-z]", "", text.lower())
    vowel_ratio = (sum(c in "aeiou" for c in letters) / len(letters)) if letters else 1
    long_words = sum(1 for w in words if len(w) >= 10)
    return vowel_ratio < 0.25 and (long_words / len(words)) > 0.35


# ---------------------------------------------------------------------------
# 1) Intake analysis
# ---------------------------------------------------------------------------

def analyze_submission(name="", organization="", role="other",
                       links="", pitch="", fee: Optional[float] = None) -> dict:

    pitch = (pitch or "").strip()
    scan = analyze_message(pitch) if len(pitch) >= 10 else None
    pitch_flags = scan["flags"] if scan else []
    pitch_pos = scan["positive_signals"] if scan else []

    # --- links ---
    link_list = [l.strip() for l in re.split(r"[,\s]+", links or "") if l.strip()]
    from backend.detector import (_url_domain, _domain_matches_company,
                                  FREE_EMAIL_PROVIDERS, SHORT_URL_DOMAINS)
    link_notes, link_good, link_bad = [], 0, 0
    for raw in link_list[:6]:
        dom = _url_domain(raw) if not EMAIL_LIKE.match(raw) else raw.split("@")[-1].lower()
        if EMAIL_LIKE.match(raw):
            dom = raw.split("@")[-1].lower()
            if dom in FREE_EMAIL_PROVIDERS:
                link_notes.append(f"✉️ '{raw}' is a free mailbox — not a corporate domain.")
                link_bad += 1
            else:
                m = _domain_matches_company(dom)
                if m:
                    link_notes.append(f"✅ Email domain matches {m}.")
                    link_good += 1
                else:
                    link_notes.append(f"❓ Email domain '{dom}' is unrecognized — verify it belongs to {organization or 'the claimed org'}.")
            continue
        m = _domain_matches_company(dom)
        if m:
            link_notes.append(f"✅ Link '{dom}' matches {m}'s known domain pattern.")
            link_good += 1
        elif dom in SHORT_URL_DOMAINS:
            link_notes.append(f"🚩 Shortened link '{dom}' hides its destination.")
            link_bad += 1
        elif raw.lower().startswith("http://"):
            link_notes.append(f"🚩 '{dom}' uses plain HTTP (no TLS).")
            link_bad += 1
        elif dom.startswith("linkedin.com") or dom.endswith(".linkedin.com") or dom == "github.com":
            link_notes.append(f"ℹ️ '{dom}' — professional profile; cross-check it matches '{name or organization}'.")
            link_good += 1
        else:
            note = f"❓ Domain '{dom}' is not a recognized company domain — verify ownership on WHOIS/MCA."
            live = livecheck.fetch_url(raw, organization)
            if live.get("fetched") and live.get("reachable"):
                if live.get("org_in_title"):
                    note = (f"✅ Live check: '{dom}' is reachable and its page title "
                            f"references '{organization}' — \"{live.get('title', '')}\".")
                    link_good += 1
                else:
                    note = (f"🌐 Live check: '{dom}' reachable (HTTP {live.get('status')}), "
                            f"page title: \"{live.get('title', 'none')}\" — does NOT clearly "
                            f"mention '{organization or 'the org'}'.")
            elif live.get("fetched") and live.get("blocked"):
                note += f" 🌐 Live check: site exists but bot-protected (HTTP {live.get('status')}) — open it in a browser to confirm."
            elif live.get("fetched"):
                note += f" 🌐 Live check: site returned an error (HTTP {live.get('status')})."
            link_notes.append(note)

    # --- unrealistic claims ---
    claims = []
    for cid, pat, label, why in UNREALISTIC_CLAIMS:
        for m in re.finditer(pat, pitch, re.I):
            claims.append({"id": cid, "label": label, "why": why, "text": m.group(0).strip()})
            break

    # --- fee evaluation ---
    fee_info = _evaluate_fee(fee, claims, pitch_flags, pitch)

    # --- credibility ---
    cred = 50
    cred -= min(len(pitch_flags), 6) * 6
    cred += min(len(pitch_pos), 3) * 5
    cred += link_good * 8
    cred -= link_bad * 8
    cred -= min(len(claims), 3) * 7
    if fee and fee > 0 and any(c["id"] in ("guaranteed_outcome", "hundred_percent") for c in claims):
        cred -= 10
    if not fee or fee <= 0:
        cred += 3
    cred = max(0, min(100, cred))

    # --- red flags / positives summary ---
    red_flags = [f["title"] for f in pitch_flags]
    red_flags += [c["label"] for c in claims]
    red_flags += [n for n in link_notes if n.startswith("🚩")]
    positives = [p["title"] for p in pitch_pos]
    positives += [n for n in link_notes if n.startswith("✅")]

    # --- choose questions ---
    topics = set()
    has_outcome_claim = any(c["id"] in ("guaranteed_outcome", "hundred_percent", "guaranteed_salary") for c in claims)
    if link_good == 0:
        topics.add("company_registration")
    if role in ("recruiter", "internship") or has_outcome_claim or re.search(r"\b(internship|placement|job)\b", pitch, re.I):
        topics.add("official_offer_letter")
        topics.add("placement_proof")
    if (fee and fee > 0) or any(f["id"] == "payment_request" for f in pitch_flags):
        topics.update(["fee_breakdown", "payment_channel"])
    if role in ("mentor", "course") or TECH_HINT.search(pitch or ""):
        topics.update(["mentor_and_project", "technical_stack", "alumni_reference"])
    topics.add("alumni_reference")

    ordered = sorted(
        (QUESTION_BANK[t] | {"topic": t} for t in topics),
        key=lambda q: -_role_boost(q["priority"], q["topic"], role),
    )[:5]
    questions = [
        {"n": i + 1, "topic": q["topic"], "question": q["question"],
         "message": q["message"], "why": q["why"]}
        for i, q in enumerate(ordered)
    ]

    return {
        "agent_version": AGENT_VERSION,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "subject": {"name": name, "organization": organization, "role": role, "fee": fee},
        "pitch_scan": ({"score": scan["score"], "verdict": scan["verdict"]["label"],
                        "flags": [f["title"] for f in pitch_flags]} if scan else None),
        "link_notes": link_notes,
        "unrealistic_claims": claims,
        "fee_evaluation": fee_info,
        "credibility": {"score": cred, "band": _credibility_band(cred)},
        "red_flags": red_flags,
        "positive_signals": positives,
        "questions": questions,
        "offline_notice": ("Agent Mode performs offline consistency & red-flag analysis. "
                           "Always confirm IDs, links and claims on official portals (MCA, GST, LinkedIn, company site)."),
    }


def _role_boost(priority, topic, role):
    if role == "mentor" and topic == "alumni_reference":
        return priority + 15
    if role == "course" and topic == "technical_stack":
        return priority + 12
    if role in ("recruiter", "internship") and topic == "official_offer_letter":
        return priority + 12
    return priority


def _evaluate_fee(fee, claims, pitch_flags, pitch):
    if not fee or fee <= 0:
        if any(f["id"] == "payment_request" for f in pitch_flags):
            fee = None  # fee mentioned only inside the pitch text
            return {
                "applicable": True, "fee": None,
                "verdict": "NOT WORTH IT",
                "reasons": ["The pitch itself demands a fee/deposit — no legitimate job or internship charges candidates."],
            }
        return {"applicable": False, "fee": 0, "verdict": "Not Applicable",
                "reasons": ["No fee stated."]}

    reasons = []
    verdict = "MAYBE WORTH IT"
    guaranteed = any(c["id"] in ("guaranteed_outcome", "hundred_percent", "guaranteed_salary") for c in claims)

    if guaranteed:
        verdict = "NOT WORTH IT"
        reasons.append("A fee bundled with a 'guaranteed' outcome is the canonical paid-placement scam pattern — verified placements are never sold.")
    if fee <= 500:
        reasons.append(f"₹{fee:g} is low, but legitimate internships/jobs never charge candidates at all.")
    elif fee <= 2000:
        reasons.append(f"₹{fee:g} needs a written GST invoice, refund policy, and named deliverables before it can be justified.")
    elif fee <= 5000:
        verdict = "NOT WORTH IT" if guaranteed else "MAYBE WORTH IT"
        reasons.append(f"₹{fee:g} is significant — demand recorded placement data, alumni references, and official receipts; compare with free alternatives (NPTEL, Coursera audit, company-run internships).")
    else:
        verdict = "NOT WORTH IT"
        reasons.append(f"₹{fee:g} is a high upfront cost with unverifiable ROI; credible alternatives exist at a fraction of this price.")

    if not reasons:
        reasons.append("Fee present without guarantees — evaluate strictly against documented deliverables.")
    return {"applicable": True, "fee": fee, "verdict": verdict, "reasons": reasons}


EMAIL_LIKE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# 2) Reply analysis
# ---------------------------------------------------------------------------

def analyze_reply(topic: str, question: str, reply: str,
                  history: Optional[list] = None, fee: Optional[float] = None) -> dict:

    history = history or []
    reply = (reply or "").strip()
    words = len(reply.split())
    digits = len(re.findall(r"\d", reply))
    urls = re.findall(r"(?:https?://|www\.)\S+|\b[A-Za-z0-9-]+\.(?:com|in|org|co|io|net)\b", reply)

    qb = QUESTION_BANK.get(topic, {})
    kw = qb.get("keywords", [])
    kw_hits = sum(1 for k in kw if k in reply.lower())
    on_topic = kw_hits >= 1

    evasion = [p for p in EVASION_PATTERNS if re.search(p, reply, re.I)]
    pressure = [p for p in PRESSURE_PATTERNS if re.search(p, reply, re.I)]

    contradiction = None
    said_free_earlier = any(
        any(re.search(p, h.get("reply", ""), re.I) for p in FREE_CLAIM_PATTERNS)
        for h in history
    )
    demands_fee_now = any(re.search(p, reply, re.I) for p in FEE_DEMAND_PATTERNS)
    if said_free_earlier and demands_fee_now:
        contradiction = "Earlier they said 'no fee'; this reply now demands a payment."

    nonsense = _looks_nonsense(reply)
    ids = livecheck.extract_identifiers(reply)

    # ---- classification ----
    if nonsense:
        category, delta = "nonsense", -8
    elif contradiction:
        category, delta = "contradicted", -10
    elif evasion:
        category, delta = "evasive", -6
    elif pressure:
        category, delta = "pressure", -6
    elif on_topic and (urls or digits >= 3) and words >= 12:
        category, delta = "specific", +5
    elif on_topic:
        category, delta = "partial", -1
    else:
        category, delta = ("vague", -4) if words < 12 else ("off_topic", -3)

    # ---- verification buckets (honest, offline) ----
    verified, partial, unverified, contradicted = [], [], [], []
    if category in ("specific", "partial"):
        verified.append("Answer addresses the asked topic (keyword evidence found).")

    # --- official identifier format validation ---
    for cin in ids["cins"][:2]:
        verified.append(f"CIN '{cin}' matches the official MCA (India) company-number format.")
        partial.append("Confirm the CIN free of charge at mca.gov.in → MCA Services → 'View Company/LLP Master Data'.")
    for g in ids["gstins"][:2]:
        verified.append(f"GSTIN '{g}' matches the official GST number format.")
        partial.append("Confirm the GSTIN at services.gst.gov.in → 'Search Taxpayer'.")

    # --- live URL fetch (real network check, graceful offline fallback) ---
    for u in urls[:2]:
        lr = livecheck.fetch_url(u)
        if lr.get("fetched") and lr.get("reachable"):
            row = f"🌐 Live check: {u} reachable (HTTP {lr.get('status')})"
            if lr.get("title"):
                row += f", page title: \"{lr['title']}\""
            if lr.get("https") is False:
                row += " — ⚠️ not HTTPS"
            partial.append(row)
        elif lr.get("fetched") and lr.get("blocked"):
            partial.append(f"🌐 {u} exists but uses bot-protection (HTTP {lr.get('status')}) — many genuine corporate sites do this; open it in a browser to confirm.")
        elif lr.get("fetched"):
            unverified.append(f"🌐 Live check: {u} returned an error (HTTP {lr.get('status')}) — verify manually.")
        else:
            unverified.append(f"🌐 Live check: {u} could not be fetched (domain may not exist, or no internet here) — verify manually.")

    # --- nonsense ---
    if nonsense:
        contradicted.append("Reply appears to be random or keyboard-mash text — it is not an answer to the question.")
    if digits >= 3 and category in ("specific", "partial"):
        partial.append("Contains concrete numbers/IDs — good sign, but confirm them on the official portal before acting.")
    if words < 12:
        unverified.append("Very short reply — insufficient detail to verify anything.")
    if not urls and category not in ("specific",):
        unverified.append("No link, document, or identifier provided — claim cannot be cross-checked.")
    if evasion:
        contradicted.append("Evasive assurance language detected ('trust me', 'no need to check') instead of evidence.")
    if pressure:
        contradicted.append("New pressure/scarcity tactic inside the reply.")
    if contradiction:
        contradicted.append(contradiction)

    CATEGORY_LABEL = {
        "specific": "Specific & on-topic", "partial": "Partially answers",
        "vague": "Vague / low detail", "off_topic": "Does not answer the question",
        "evasive": "Evasive — reassurance instead of evidence",
        "pressure": "Pressure tactics", "contradicted": "Contradicts earlier statement",
        "nonsense": "Random text — not an answer",
    }

    # ---- next question ----
    used = {topic} | {h.get("topic") for h in history}
    if category in ("evasive", "pressure", "vague", "off_topic", "contradicted") and qb:
        nxt = {"topic": topic, "question": qb["drill"],
               "message": qb["drill"],
               "why": "The previous answer did not provide verifiable evidence — pressing for specifics on the same topic."}
    else:
        nxt = None
        for t in DEFAULT_QUEUE:
            if t not in used:
                q = QUESTION_BANK[t]
                nxt = {"topic": t, "question": q["question"], "message": q["message"],
                       "why": q["why"]}
                break

    return {
        "agent_version": AGENT_VERSION,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "reply_category": category,
        "reply_category_label": CATEGORY_LABEL[category],
        "credibility_delta": delta,
        "reply_verification": {
            "verified": verified, "partial": partial,
            "unverified": unverified, "contradicted": contradicted,
        },
        "stats": {"words": words, "topic_keywords_matched": kw_hits, "links_found": len(urls)},
        "next_question": nxt,
        "offline_notice": ("CIN/GSTIN formats and (when the server is online) shared links are "
                           "checked automatically; always confirm IDs on official portals "
                           "(mca.gov.in, services.gst.gov.in) before trusting them."),
    }

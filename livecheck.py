"""
Optional live web verification for ScamCheck Agent Mode.

- extract_identifiers(): pulls CIN, GSTIN, URLs, emails out of any text and
  validates their official registration formats (MCA / GST structures).
- fetch_url(): performs a real HTTP GET (if the server has internet access)
  and reports reachability, final URL, HTTPS, page <title>, and whether the
  claimed organization's name appears in the title.

Everything degrades gracefully: with no network (or httpx missing) every check
simply reports 'offline — verify manually'.
"""

from __future__ import annotations

import re

try:
    import httpx
    HAVE_HTTPX = True
except Exception:  # pragma: no cover
    HAVE_HTTPX = False

# Official formats ------------------------------------------------------------
# CIN  e.g. U74999TN2019PTC123456  (MCA India)
CIN_RE = re.compile(r"\b[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b")
# GSTIN e.g. 33ABCDE1234F1Z5  (GST India)
GSTIN_RE = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s\"'<>)\]]+|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\."
    r"(?:com|in|org|co|io|net|edu|ac\.in|co\.in)(?:/[^\s\"'<>)\]]*)?",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def extract_identifiers(text: str) -> dict:
    """Find registration identifiers & references inside free text."""
    return {
        "cins": sorted(set(CIN_RE.findall(text or ""))),
        "gstins": sorted(set(GSTIN_RE.findall(text or ""))),
        "urls": sorted(set(u.rstrip(".,;!") for u in URL_RE.findall(text or ""))),
        "emails": sorted(set(EMAIL_RE.findall(text or ""))),
    }


def fetch_url(url: str, organization: str = "", timeout: float = 6.0) -> dict:
    """Attempt a real HTTP GET and summarize what came back."""
    result = {"url": url, "fetched": False, "reachable": False}
    if not HAVE_HTTPX:
        return result
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    try:
        with httpx.Client(
            follow_redirects=True, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (ScamCheck verifier/1.1)"},
        ) as client:
            r = client.get(url)
        result.update(
            fetched=True,
            reachable=r.status_code < 400,
            blocked=r.status_code in (401, 403, 429),
            status=r.status_code,
            final_url=str(r.url),
            https=r.url.scheme == "https",
        )
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:200_000], re.IGNORECASE | re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""
        result["title"] = title
        if organization and title:
            toks = [t for t in re.split(r"[^A-Za-z0-9]+", organization.lower()) if len(t) >= 3]
            result["org_in_title"] = any(t in title.lower() for t in toks)
    except Exception:
        # DNS failure, TLS error, timeout, no egress -> stay 'not fetched'
        pass
    return result

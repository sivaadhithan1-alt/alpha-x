"""Curated demo samples — used by the UI 'Try a sample' buttons and the tests.

Each sample exercises a different path through the scoring engine so judges can
verify the full verdict range in seconds.
"""

SAMPLES = [
    {
        "id": "obvious_scam",
        "label": "Obvious Scam",
        "icon": "🔴",
        "expected": "High Risk — Likely Scam",
        "message": (
            "CONGRATULATIONS!! You have been SELECTED for the Wipro Work From "
            "Home Internship Program. Earn ₹45,000/month working just 2 hours a "
            "day. NO interview required and no experience needed! Only 3 slots "
            "left - this offer expires today!! To confirm your seat, pay a "
            "refundable registration fee of ₹999 via UPI. Also share your "
            "Aadhaar card and bank details for verification. Apply fast at "
            "bit.ly/wipro-apply or contact HR on WhatsApp: 9876543210"
        ),
        "sender_email": "wiprocarrers@gmail.com",
    },
    {
        "id": "sneaky_scam",
        "label": "Sneaky Scam",
        "icon": "🟠",
        "expected": "High Risk — Likely Scam",
        "message": (
            "Dear Candidate, Thank you for your interest in the Software "
            "Trainee position at Tech Mahindra. Based on your profile, you have "
            "been shortlisted for the next stage. To initiate onboarding and "
            "background verification, a refundable security deposit of ₹1,500 "
            "is required, which will be returned along with your first month's "
            "salary. Kindly complete this step within 24 hours to secure your "
            "position. For any queries, you may reach our HR desk on WhatsApp "
            "at +91 9812345678. Regards, Talent Acquisition Team"
        ),
        "sender_email": "careers@talentbridge-hr.com",
    },
    {
        "id": "borderline_offer",
        "label": "Borderline Offer",
        "icon": "🟡",
        "expected": "Proceed with Caution",
        "message": (
            "Hi! We are Sunrise EdTech, a fast-growing startup. We're hiring "
            "Campus Ambassadors for colleges across Tamil Nadu. Stipend up to "
            "₹4,000/month based on performance. Limited slots available, so "
            "apply soon! To apply, ping us on WhatsApp at 9845012345 with your "
            "name and college. Duration: 3 months, part-time, work from campus."
        ),
        "sender_email": "openings.sunriseedtech@gmail.com",
    },
    {
        "id": "genuine_offer",
        "label": "Genuine Offer",
        "icon": "🟢",
        "expected": "Looks Safe",
        "message": (
            "Dear Applicant, Thank you for applying to the TCS Digital "
            "Internship Program 2026. We are pleased to inform you that your "
            "application has been shortlisted for the next stage of the "
            "selection process. The process consists of two rounds: an online "
            "assessment followed by a technical interview. Tentative dates and "
            "preparation resources are available on our official careers "
            "portal: https://www.tcs.com/careers/internships. Please note that "
            "Tata Consultancy Services never requests any payment or deposit "
            "at any stage of recruitment. Regards, TCS Campus Hiring Team"
        ),
        "sender_email": "careers@tcs.com",
    },
]

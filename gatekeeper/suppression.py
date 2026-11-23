"""A suppression is absolute; approvals never override it."""
from .storage import suppression_id

import re

# CTIA's standard STOP family plus REVOKE and OPTOUT, the words the FCC's 2025 revocation
# rule names (47 CFR 64.1200(a)(10)); CANCEL stays in on the broader TCPA reading.
KEYWORDS = ("STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT", "REVOKE", "OPTOUT")


def normalize(text):
    """Whole message, case-insensitive; inner spaces, hyphens and underscores and trailing
    punctuation are ignored, so "Opt out", "opt-out" and "Stop." all match."""
    return re.sub(r"[\s_-]+", "", text.strip().rstrip(".!").upper())


def is_stop(text, keywords=KEYWORDS):
    return isinstance(text, str) and normalize(text) in keywords


def check(db, recipient):
    if db.execute("SELECT 1 FROM suppressions WHERE recipient_id=?", (suppression_id(recipient),)).fetchone():
        return "block", "suppressed"
    return None

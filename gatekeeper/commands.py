"""Owner administration only; never registered as an agent tool."""
from datetime import datetime, timezone
import json
import shlex

from . import consent, history
from .storage import recipient_id
from .wording import validate_variables

USAGE = ("Usage: /gatekeeper [log [1-50] | resume | optout <recipient> | "
         "consent <recipient> <channel> <source> <YYYY-MM-DD> <timezone|unknown> [region] | "
         "revoke <recipient> <channel> | reply <recipient> <channel> [thread] | "
         "variables <recipient> <channel> '<JSON object>']")


def _field(source, name):
    value = source.get(name) if isinstance(source, dict) else getattr(source, name, None)
    return getattr(value, "value", value)


def _local_context(platform, source):
    """True only for a local terminal/desktop session.

    The classic CLI, TUI and Desktop run plugin commands in the gateway that owns the
    session, which passes ``platform="local"`` and a ``SessionSource`` whose platform is
    local. Messaging platforms, or any source naming another platform, are refused.
    """
    if platform not in {"cli", "tui", "desktop", "local"}:
        return False
    if source is None:
        return True
    return _field(source, "platform") == "local"


def _owner_context(platform, source, owner_ids):
    """True for a direct chat from a configured ``platform:user_id`` owner identity.

    The host's gateway passes the authenticated ``SessionSource`` of the message that
    carried the command; its platform must agree with the ``platform`` keyword. Group
    chats are refused so records are never read out to other participants.
    """
    if not owner_ids or source is None or not isinstance(platform, str) or not platform:
        return False
    if _field(source, "platform") != platform or _field(source, "chat_type") != "dm":
        return False
    user = _field(source, "user_id")
    return isinstance(user, str) and bool(user) and f"{platform}:{user}" in owner_ids


def command(service, raw="", *, platform="", source=None, **kwargs):
    # Public calling-session keywords (plugin developer guide, slash commands).
    if not (_local_context(platform, source) or _owner_context(platform, source, service.settings.owner_ids)):
        return "Only the owner can manage texting consent and opt-outs."
    try:
        parts = shlex.split(raw)
        if parts == ["resume"]:
            # The owner has reviewed an opt-out that could not be tied to a sender.
            if not service.unhealthy.is_set():
                return "Gatekeeper: ready; nothing to resume."
            if service.recover(owner=True):
                return "Gatekeeper: storage is readable again; held opt-outs were saved and sends resume."
            return "Gatekeeper could not read or change its record. Sends stay blocked."
        if not parts:
            service.recover()  # outside the transaction below: recovery opens its own
        with service.ledger.transaction() as db:
            if not parts:
                counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                          for table in ("suppressions", "contacts", "decisions")}
                state = ("needs attention: settings are invalid" if service.config_error else
                         f"needs attention: {service.health_reason}; sends blocked" if service.unhealthy.is_set() else "ready")
                return (f"Gatekeeper: {state}; suppressed: {counts['suppressions']}; "
                        f"contacts: {counts['contacts']}; decisions: {counts['decisions']}. "
                        "Only hook-visible sends are gated. " + USAGE)
            name, args = parts[0], parts[1:]
            if name == "log" and len(args) <= 1:
                count = int(args[0]) if args else 10
                if not 1 <= count <= 50:
                    raise ValueError("invalid limit")
                rows = db.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (count,)).fetchall()
                return "\n".join(f"{datetime.fromtimestamp(r['at'], timezone.utc).isoformat()} | {r['channel']} | "
                                 f"{r['recipient_id'][:12]} | {r['rule']} | {r['outcome']}" for r in rows) or "No decisions yet."
            if name == "optout" and len(args) == 1:
                service.ledger.optout(db, args[0])
                return "Gatekeeper: recipient suppressed. Approval and new consent cannot override suppression."
            if name == "consent" and len(args) in {5, 6}:
                recipient, channel, origin, date, zone, *region = args
                consent.record(db, recipient, channel, origin, date, "" if zone == "unknown" else zone, region[0] if region else "")
                return "Gatekeeper: channel consent recorded; suppression still applies."
            if name == "revoke" and len(args) == 2:
                consent.revoke(db, *args)
                return "Gatekeeper: channel consent revoked."
            if name == "reply" and len(args) in {2, 3}:
                history.reply(db, args[0], args[1], args[2] if len(args) == 3 else "", at=service.now().timestamp(), owner=True)
                return "Gatekeeper: owner-observed reply recorded. No consent was granted."
            if name == "variables" and len(args) == 3:
                recipient, channel, raw_values = args
                values = validate_variables(json.loads(raw_values))
                if not consent.contact(db, recipient, channel):
                    raise ValueError("record contact first")
                db.execute("UPDATE contacts SET variables=? WHERE recipient_id=? AND channel=?",
                           (json.dumps(values, sort_keys=True), recipient_id(recipient), channel))
                return "Gatekeeper: owner template variables saved."
        return USAGE
    except (ValueError, TypeError):
        return USAGE
    except Exception:
        return "Gatekeeper could not read or change its record. Check local storage and settings."
